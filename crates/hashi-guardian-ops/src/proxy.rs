// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian proxy's stack, applied from the sui-operations checkout beside the enclave stack so the proxy follows
//! the enclave stack's slots. Following them changes only the proxy task's two guardian URLs; anything else in a plan
//! stops the step.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use serde_json::Value;

use crate::Ctx;
use crate::ask::NOTHING_CHANGED;
use crate::ask::confirm;
use crate::exec::Cmd;
use crate::exec::read;
use crate::guardian::proxy_health;
use crate::guardian::relay_info;
use crate::plan::Change;
use crate::plan::Plan;
use crate::plan::preview;
use crate::plan::require_pulumi_version;
use crate::plan::up;
use crate::stack::Stack;
use crate::stack::export;
use crate::stack::pulumi;
use crate::warn;

const TASK_DEFINITION: &str = "::aws:ecs/taskDefinition:TaskDefinition::";
const SERVICE: &str = "::aws:ecs/service:Service::";
const URL_KEYS: [&str; 2] = ["GUARDIAN_BACKEND_URL", "STANDBY_GUARDIAN_URL"];

/// The proxy stack's Pulumi program, beside the enclave stack's.
pub fn proxy_dir(stack: &Stack) -> String {
    Path::new(&stack.dir)
        .parent()
        .unwrap_or(Path::new("."))
        .join("hashi-guardian-proxy")
        .display()
        .to_string()
}

/// Applies the proxy stack so it follows the enclave stack's slots. It builds no image: the proxy step does.
pub fn update_proxy(ctx: &Ctx, stack: &Stack, tree: &crate::commit::Tree) -> Result<()> {
    // The relay holds a provisioning round's shares in memory, so a roll during one drops them.
    match relay_info(ctx, tree) {
        Ok(relay) if relay.lifecycle.in_kp_round() => bail!(
            "The guardian the relay serves is in a key provisioner round ({}). Update the proxy once that round has finished.",
            relay.lifecycle
        ),
        Ok(_) => {}
        Err(_) => warn(&format!(
            "The proxy's relay does not answer at {}, so no key provisioner round runs through it.",
            ctx.env.proxy_url()?.authority
        )),
    }
    let dir = proxy_dir(stack);
    if !Path::new(&dir).is_dir() {
        bail!("No guardian proxy Pulumi program at {dir}.");
    }
    require_pulumi_version(ctx, &dir, stack)?;
    let config = |key: &str| {
        read(
            ctx.exec,
            &pulumi(&dir).args(["config", "get", key, "--stack", &stack.name]),
        )
        .map(|value| value.trim().to_owned())
    };
    let configured = config("hashi-guardian-proxy:proxy-image-tag")
        .with_context(|| format!("Stack {} in {dir} has no proxy-image-tag.", stack.name))?;
    let region = config("hashi-guardian-proxy:aws-region")
        .with_context(|| format!("Stack {} in {dir} has no aws-region.", stack.name))?;
    // The plan below comes from Pulumi's state, not a refresh, since a refresh would also act on drift elsewhere in
    // the stack, such as DNS records someone else manages. So read the service from ECS, which also rolls a failed
    // deployment back by itself.
    let ecs = running_service(ctx, &dir, stack, &region).with_context(|| {
        format!(
            "Could not read the proxy service of stack {} from ECS.",
            stack.name
        )
    })?;
    if ecs.desired < 1 || ecs.running != ecs.desired || ecs.deployments != 1 {
        bail!(
            "The proxy service runs {} of {} tasks in {} deployments. Wait for it to settle, or bring it back with a refreshed pulumi up of the proxy stack, before this step.",
            ecs.running,
            ecs.desired,
            ecs.deployments
        );
    }
    if ecs.image.rsplit(':').next() != Some(configured.as_str()) {
        bail!(
            "The proxy runs {}, but {dir} configures tag {configured}. This step does not build images: roll a new proxy build with the proxy step.",
            ecs.image
        );
    }
    let plan = preview(ctx, &dir, &stack.name, None)
        .map_err(|_| anyhow!("Could not preview the proxy stack {}.", stack.name))?;
    let changes = plan.changes();
    if changes.is_empty() {
        println!("The proxy already follows stack {}.", stack.name);
        return Ok(());
    }
    println!("Proxy plan:");
    for change in &changes {
        println!("{} {}", change.op, change.urn);
    }
    let unexpected: Vec<String> = changes
        .iter()
        .filter(|change| !follows_slots(change))
        .map(|change| format!("{} {}", change.op, change.urn))
        .collect();
    if !unexpected.is_empty() {
        bail!(
            "The proxy plan changes more than its task definition and service. Nothing was changed; find out why first: {}",
            unexpected.join("\n")
        );
    }
    let (backend, standby) = guardian_urls(&plan).map_err(|_| {
        anyhow!(
            "The proxy plan changes the proxy task by more than its guardian URLs, or could not be compared. Nothing was changed: read pulumi preview --diff for stack {} in {dir}.",
            stack.name
        )
    })?;
    let active_ip = stack.output("guardian_private_ip").unwrap_or("");
    if backend != format!("http://{active_ip}:3000") {
        bail!(
            "The proxy plan sends nodes to {backend}, not to the active guardian at {active_ip}."
        );
    }
    match stack.output("standby_private_ip") {
        Some(ip) if standby.as_deref() != Some(&format!("http://{ip}:3000")) => bail!(
            "The proxy plan relays key provisioners to {}, not to the standby at {ip}.",
            standby.as_deref().unwrap_or("no guardian")
        ),
        None if standby.is_some() => bail!(
            "The proxy plan relays key provisioners to {}, but stack {} has no standby.",
            standby.as_deref().unwrap_or(""),
            stack.name
        ),
        _ => {}
    }
    println!(
        "The proxy will send nodes to {backend} and key provisioners to {}.",
        standby.as_deref().unwrap_or(&backend)
    );
    warn(
        "Updating the proxy restarts it: the guardian's address is down for some minutes, and nodes retry their requests.",
    );
    confirm(
        ctx.ask,
        &format!("Update the proxy of stack {}?", stack.name),
        &NOTHING_CHANGED,
    )?;
    if !up(ctx, &dir, &stack.name, None)? {
        bail!("The proxy update did not finish. Run this step again: it previews the proxy first.");
    }
    let url = ctx.env.proxy_url()?.url;
    proxy_health(ctx)
        .with_context(|| format!("The proxy updated but {url}/health does not answer."))?;
    Ok(())
}

/// Following the guardian slots changes only the task's guardian URLs, which replaces its definition and points the
/// service at the new one.
fn follows_slots(change: &Change) -> bool {
    (matches!(
        change.op.as_str(),
        "replace" | "create-replacement" | "delete-replaced" | "update"
    ) && change.urn.contains(TASK_DEFINITION))
        || (change.op == "update" && change.urn.contains(SERVICE))
}

/// The guardian URLs the plan's one task definition change sets, once nothing else about the proxy container or the
/// service changes.
fn guardian_urls(plan: &Plan) -> Result<(String, Option<String>)> {
    let mut urls = Vec::new();
    for step in plan
        .steps
        .iter()
        .filter(|step| step.urn.contains(TASK_DEFINITION))
    {
        let container = |state: &Option<Value>| -> Option<Value> {
            let definitions = state.as_ref()?.get("inputs")?.get("containerDefinitions")?;
            let definitions: Value = serde_json::from_str(definitions.as_str()?).ok()?;
            definitions
                .as_array()?
                .iter()
                .find(|container| container.get("name") == Some(&Value::from("proxy")))
                .cloned()
        };
        let (Some(old), Some(new)) = (container(&step.old_state), container(&step.new_state))
        else {
            continue;
        };
        if without_urls(&old) == without_urls(&new) {
            urls.push((
                url(&new, URL_KEYS[0]).unwrap_or_default(),
                url(&new, URL_KEYS[1]),
            ));
        }
    }
    if urls.len() != 1 {
        bail!("not one comparable task definition");
    }
    let (backend, standby) = urls.remove(0);
    let service_changes_only_its_task = plan
        .steps
        .iter()
        .filter(|step| step.urn.contains(SERVICE))
        .all(|step| {
            step.detailed_diff
                .as_ref()
                .and_then(Value::as_object)
                .is_none_or(|diff| diff.keys().all(|key| key == "taskDefinition"))
        });
    if !service_changes_only_its_task {
        bail!("the service changes by more than its task definition");
    }
    Ok((backend, standby))
}

/// A container with its guardian URLs left out and its environment in name order.
fn without_urls(container: &Value) -> Value {
    let mut container = container.clone();
    let mut environment: Vec<Value> = container
        .get("environment")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| {
            !URL_KEYS
                .iter()
                .any(|key| entry.get("name") == Some(&Value::from(*key)))
        })
        .collect();
    environment.sort_by_key(|entry| {
        entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });
    container["environment"] = Value::Array(environment);
    container
}

fn url(container: &Value, key: &str) -> Option<String> {
    container
        .get("environment")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("name") == Some(&Value::from(key)))?
        .get("value")?
        .as_str()
        .map(str::to_owned)
}

struct Ecs {
    desired: u64,
    running: u64,
    deployments: u64,
    image: String,
}

fn running_service(ctx: &Ctx, dir: &str, stack: &Stack, region: &str) -> Result<Ecs> {
    let service = export(ctx, dir, &stack.name)?
        .deployment
        .resources
        .into_iter()
        .find(|resource| resource.kind == "aws:ecs/service:Service")
        .and_then(|resource| resource.outputs)
        .context("The proxy stack's state has no ECS service.")?;
    let field = |key: &str| {
        service
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .with_context(|| format!("The proxy's ECS service has no {key}."))
    };
    let (cluster, name) = (field("cluster")?, field("name")?);
    let counts = read(
        ctx.exec,
        &Cmd::new("aws")
            .args(["ecs", "describe-services", "--region", region])
            .args(["--cluster", &cluster, "--services", &name, "--output", "text"])
            .args([
                "--query",
                "services[0].[desiredCount, runningCount, length(deployments), deployments[?status==`PRIMARY`].taskDefinition | [0]]",
            ]),
    )?;
    let fields: Vec<&str> = counts.split_whitespace().collect();
    let [desired, running, deployments, task_definition] = fields[..] else {
        bail!("ECS described the service as: {}", counts.trim());
    };
    let image = read(
        ctx.exec,
        &Cmd::new("aws")
            .args(["ecs", "describe-task-definition", "--region", region])
            .args(["--task-definition", task_definition])
            .args([
                "--query",
                "taskDefinition.containerDefinitions[?name==`proxy`].image | [0]",
                "--output",
                "text",
            ]),
    )?;
    let count = |value: &str| {
        value
            .parse::<u64>()
            .with_context(|| format!("ECS reported {value} as a count."))
    };
    Ok(Ecs {
        desired: count(desired)?,
        running: count(running)?,
        deployments: count(deployments)?,
        image: image.trim().to_owned(),
    })
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use super::*;

    /// A container definition as the task definition's inputs hold it: a JSON string.
    pub fn definitions(backend: &str, standby: Option<&str>, image: &str) -> String {
        let mut environment = vec![
            json!({ "name": "GUARDIAN_BACKEND_URL", "value": backend }),
            json!({ "name": "SUI_RPC_URL", "value": "https://fullnode.testnet.sui.io:443" }),
        ];
        if let Some(standby) = standby {
            environment.push(json!({ "name": "STANDBY_GUARDIAN_URL", "value": standby }));
        }
        json!([{ "name": "proxy", "image": image, "environment": environment }]).to_string()
    }

    pub fn proxy_plan(old: &str, new: &str, service_diff: Value) -> Plan {
        serde_json::from_value(json!({
            "steps": [
                {
                    "op": "replace",
                    "urn": "urn:pulumi:testnet::hashi-guardian-proxy::aws:ecs/taskDefinition:TaskDefinition::t",
                    "oldState": { "inputs": { "containerDefinitions": old } },
                    "newState": { "inputs": { "containerDefinitions": new } },
                },
                {
                    "op": "update",
                    "urn": "urn:pulumi:testnet::hashi-guardian-proxy::aws:ecs/service:Service::s",
                    "detailedDiff": service_diff,
                },
                { "op": "read", "urn": "urn:pulumi:testnet::hashi-guardian-proxy::pulumi:pulumi:StackReference::mysten/hashi-guardian-enclave/testnet" },
            ],
        }))
        .unwrap()
    }

    #[test]
    fn finds_the_guardian_urls_a_plan_sets() {
        let old = definitions("http://192.0.2.1:3000", None, "repo:tag");
        let new = definitions(
            "http://192.0.2.1:3000",
            Some("http://192.0.2.2:3000"),
            "repo:tag",
        );
        let plan = proxy_plan(
            &old,
            &new,
            json!({ "taskDefinition": { "kind": "update" } }),
        );
        assert_eq!(
            guardian_urls(&plan).unwrap(),
            (
                "http://192.0.2.1:3000".to_owned(),
                Some("http://192.0.2.2:3000".to_owned())
            )
        );
        assert!(plan.changes().iter().all(follows_slots));
    }

    #[test]
    fn refuses_a_plan_that_changes_anything_else() {
        let old = definitions("http://192.0.2.1:3000", None, "repo:tag");
        let new_image = definitions("http://192.0.2.1:3000", None, "repo:other");
        assert!(guardian_urls(&proxy_plan(&old, &new_image, json!({}))).is_err());
        let new = definitions("http://192.0.2.2:3000", None, "repo:tag");
        assert!(
            guardian_urls(&proxy_plan(
                &old,
                &new,
                json!({ "taskDefinition": {}, "desiredCount": {} })
            ))
            .is_err()
        );
        assert!(!follows_slots(&Change::new(
            "delete",
            "urn:pulumi:testnet::hashi-guardian-proxy::aws:ecs/service:Service::s"
        )));
        assert!(!follows_slots(&Change::new(
            "update",
            "urn:pulumi:testnet::hashi-guardian-proxy::aws:route53/record:Record::r"
        )));
    }
}

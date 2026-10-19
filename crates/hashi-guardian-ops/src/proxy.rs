// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian proxy's stack, applied from its program at `GUARDIAN_PROXY_PULUMI_DIR` so the proxy follows the enclave
//! stack's slots. Following them changes only the proxy task's two guardian URLs; anything else in a plan stops the
//! step.

use std::fmt;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use serde_json::Value;

use crate::Ctx;
use crate::ask::Unchanged;
use crate::ask::confirm;
use crate::commit::Tree;
use crate::commit::resolve;
use crate::exec::Cmd;
use crate::exec::read;
use crate::exec::read_json;
use crate::github::require_no_guardian_runs;
use crate::guardian::proxy_health;
use crate::guardian::relay_info;
use crate::plan::Change;
use crate::plan::Plan;
use crate::plan::preview;
use crate::plan::require_pulumi_version;
use crate::plan::up;
use crate::print_detail;
use crate::print_info;
use crate::print_warning;
use crate::stack::Stack;
use crate::stack::export;
use crate::stack::project_name;
use crate::stack::pulumi;

const TASK_DEFINITION: &str = "::aws:ecs/taskDefinition:TaskDefinition::";
const SERVICE: &str = "::aws:ecs/service:Service::";
const URL_KEYS: [&str; 2] = ["GUARDIAN_BACKEND_URL", "STANDBY_GUARDIAN_URL"];

/// The proxy stack's Pulumi program, whose stack has the enclave stack's name.
fn proxy_dir(ctx: &Ctx) -> Result<String> {
    let dir = ctx.env.require("GUARDIAN_PROXY_PULUMI_DIR")?;
    project_name(dir)?;
    Ok(dir.to_owned())
}

/// Where the proxy sends nodes, and the standby its relay sends key provisioners to instead of the active guardian.
#[derive(Debug, PartialEq, Eq)]
struct Urls {
    backend: String,
    standby: Option<String>,
}

impl Urls {
    /// The URLs a proxy container's environment sets.
    fn of(container: &Value) -> Self {
        Self {
            backend: url(container, URL_KEYS[0]).unwrap_or_default(),
            standby: url(container, URL_KEYS[1]).filter(|url| !url.is_empty()),
        }
    }

    /// The URLs that follow the enclave stack's slots.
    fn following(stack: &Stack) -> Result<Self> {
        let url = |key| stack.output(key).map(|ip| format!("http://{ip}:3000"));
        Ok(Self {
            backend: url("guardian_private_ip")
                .with_context(|| format!("stack {} has no guardian_private_ip", stack.name))?,
            standby: url("standby_private_ip"),
        })
    }

    /// The guardian the relay serves.
    fn relay(&self) -> &str {
        self.standby.as_deref().unwrap_or(&self.backend)
    }
}

impl fmt::Display for Urls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "nodes to {} and key provisioners to {}",
            self.backend,
            self.relay()
        )
    }
}

/// Applies the proxy stack so it follows the enclave stack's slots. It builds no image: the proxy step does.
/// `unchanged` says what declining leaves, and `last_check` runs right before the update applies, after every other
/// check, so a caller's deadline holds.
pub fn update_proxy(
    ctx: &Ctx,
    stack: &Stack,
    tree: &Tree,
    unchanged: &Unchanged,
    last_check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let dir = proxy_dir(ctx)?;
    require_pulumi_version(ctx)?;
    let configured = config(ctx, &dir, stack, "proxy-image-tag")?;
    let region = config(ctx, &dir, stack, "aws-region")?;
    let following = Urls::following(stack)?;
    // The plan below comes from Pulumi's state, not a refresh, since a refresh would also act on drift elsewhere in
    // the stack. So what the proxy runs is read from ECS, which also rolls a failed deployment back by itself.
    let ecs = settled_service(ctx, &dir, stack, &region)?;
    if ecs.urls == following {
        print_info(&format!("The proxy already follows stack {}.", stack.name));
        return Ok(());
    }
    let plan = checked_plan(ctx, &dir, stack, &configured, &ecs, &following)?;
    print_info("Proxy plan:");
    for change in &plan {
        print_detail(&format!("{} {}", change.op, change.urn));
    }
    // A relay that serves a host the enclave stack no longer has can't be running a round through it.
    let relay = ecs.urls.relay();
    let relay_left = relay != following.backend && Some(relay) != following.standby.as_deref();
    require_no_kp_round(ctx, tree, relay_left)?;
    last_check()?;
    print_info(&format!("The proxy will send {following}."));
    print_warning(
        "Updating the proxy restarts it: the guardian's address is down for some minutes, and nodes retry their requests.",
    );
    confirm(
        ctx.ask,
        &format!("Update the proxy of stack {}?", stack.name),
        unchanged,
    )?;
    // The question can wait any time, while a workflow or a round starts.
    let now = settled_service(ctx, &dir, stack, &region)?;
    if now != ecs || checked_plan(ctx, &dir, stack, &configured, &now, &following)? != plan {
        bail!(
            "the proxy's service or plan changed while this step waited for you; the proxy was not updated: run this step again"
        );
    }
    require_no_kp_round(ctx, tree, relay_left)?;
    require_no_guardian_runs(ctx)?;
    last_check()?;
    if !up(ctx, &dir, &stack.name, None)? {
        bail!("the proxy update did not finish; run this step again: it reads what ECS runs first");
    }
    let after = settled_service(ctx, &dir, stack, &region)?;
    if after.task_definition != after.state_task_definition || after.urls != following {
        bail!(
            "the proxy update finished, but ECS runs task definition {}, which sends {}, not {}: its deployment rolled back; find out why from the service's events before going on",
            after.task_definition,
            after.urls,
            after.state_task_definition
        );
    }
    let url = ctx.env.proxy_url()?.url;
    proxy_health(ctx)
        .with_context(|| format!("the proxy updated but {url}/health does not answer"))?;
    Ok(())
}

/// The changes of a proxy plan that moves what ECS runs, `ecs`, to `following`, and nothing else.
fn checked_plan(
    ctx: &Ctx,
    dir: &str,
    stack: &Stack,
    configured: &str,
    ecs: &Ecs,
    following: &Urls,
) -> Result<Vec<Change>> {
    // The plan starts from the state, so it must be what ECS runs.
    if ecs.task_definition != ecs.state_task_definition {
        bail!(
            "ECS runs the proxy's task definition {}, which sends {}, but Pulumi's state records {}: a deployment rolled back, or the service changed outside Pulumi; find out why from the service's events, then bring the proxy back with a refreshed pulumi up of its stack",
            ecs.task_definition,
            ecs.urls,
            ecs.state_task_definition
        );
    }
    if ecs.image.rsplit(':').next() != Some(configured) {
        bail!(
            "the proxy runs {}, but {dir} configures tag {configured}; this step does not build images: roll a new proxy build with the proxy step",
            ecs.image
        );
    }
    let plan = preview(ctx, dir, &stack.name, None)
        .map_err(|_| anyhow!("could not preview the proxy stack {}", stack.name))?;
    let changes = plan.changes();
    if changes.is_empty() {
        bail!(
            "the proxy plan changes nothing, but the proxy sends {} and stack {}'s slots need it to send {following}; the proxy was not updated: check which enclave stack the proxy program reads",
            ecs.urls,
            stack.name
        );
    }
    let unexpected: Vec<String> = changes
        .iter()
        .filter(|change| !follows_slots(change))
        .map(|change| format!("{} {}", change.op, change.urn))
        .collect();
    if !unexpected.is_empty() {
        bail!(
            "the proxy plan changes more than its task definition and service; the proxy was not updated; find out why first: {}",
            unexpected.join("\n")
        );
    }
    let planned = guardian_urls(&plan).map_err(|error| {
        anyhow!(
            "{error}; the proxy was not updated: read pulumi preview --diff for stack {} in {dir}",
            stack.name
        )
    })?;
    if planned != *following {
        bail!(
            "the proxy plan sends {planned}, but stack {}'s slots need it to send {following}; the proxy was not updated",
            stack.name
        );
    }
    Ok(changes)
}

/// Stops while a key provisioner round runs through the relay, which holds a provisioning round's shares in memory, so
/// a roll during one drops them. Only a relay whose guardian the stack no longer runs may go unread.
fn require_no_kp_round(ctx: &Ctx, tree: &Tree, relay_left: bool) -> Result<()> {
    match relay_info(ctx, tree) {
        Ok(relay) if relay.lifecycle.in_kp_round() => bail!(
            "the guardian the relay serves is in a key provisioner round ({}); update the proxy once that round has finished",
            relay.lifecycle
        ),
        Ok(_) => Ok(()),
        Err(_) if relay_left => {
            print_info("The relay serves a host the enclave stack no longer runs, which does not answer.");
            Ok(())
        }
        Err(error) => Err(error.context(
            "could not read the guardian the proxy's relay serves, so a key provisioner round may run through it; update the proxy once it answers",
        )),
    }
}

/// The commit the proxy stack's image is built from: its tag is the commit, then any features.
pub fn image_commit(ctx: &Ctx, stack: &Stack) -> Result<String> {
    let dir = proxy_dir(ctx)?;
    let tag = config(ctx, &dir, stack, "proxy-image-tag")?;
    resolve(ctx, tag.split('-').next().unwrap_or_default())?.ok_or_else(|| {
        anyhow!(
            "the proxy's image tag {tag} names no commit this checkout has, so nothing can check that the proxy decodes the standby's build; fetch it first"
        )
    })
}

fn config(ctx: &Ctx, dir: &str, stack: &Stack, key: &str) -> Result<String> {
    read(
        ctx.exec,
        &pulumi(dir).args(["config", "get", key, "--stack", &stack.name]),
    )
    .map(|value| value.trim().to_owned())
    .with_context(|| format!("stack {} in {dir} has no {key}", stack.name))
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

/// The guardian URLs the plan's one task definition replacement sets, once it changes nothing else about the task,
/// and the service changes only its task definition.
fn guardian_urls(plan: &Plan) -> Result<Urls> {
    let inputs = |state: &Option<Value>| state.as_ref()?.get("inputs").cloned();
    let mut found = Vec::new();
    for step in plan
        .steps
        .iter()
        .filter(|step| step.urn.contains(TASK_DEFINITION))
    {
        // The old definition's own deletion has no new state.
        let (Some(old), Some(new)) = (inputs(&step.old_state), inputs(&step.new_state)) else {
            continue;
        };
        let (Some((old, _)), Some((new, urls))) = (split_urls(old), split_urls(new)) else {
            bail!("the proxy plan's task definition has containers this step cannot read");
        };
        let differing = differing(&old, &new);
        if !differing.is_empty() {
            bail!(
                "the proxy plan changes the proxy's task by more than its guardian URLs: {}",
                differing.join(", ")
            );
        }
        found.push(urls);
    }
    let Ok([urls]) = <[Urls; 1]>::try_from(found) else {
        bail!("the proxy plan does not replace exactly one task definition");
    };
    for step in plan.steps.iter().filter(|step| step.urn.contains(SERVICE)) {
        let (Some(mut old), Some(mut new)) = (inputs(&step.old_state), inputs(&step.new_state))
        else {
            bail!("the proxy plan's service update has no inputs this step can compare");
        };
        for inputs in [&mut old, &mut new] {
            if let Some(inputs) = inputs.as_object_mut() {
                inputs.remove("taskDefinition");
            }
        }
        let differing = differing(&old, &new);
        if !differing.is_empty() {
            bail!(
                "the proxy plan changes the proxy's service by more than its task definition: {}",
                differing.join(", ")
            );
        }
    }
    Ok(urls)
}

/// The inputs whose values differ between two sets of them.
fn differing(old: &Value, new: &Value) -> Vec<String> {
    let (Some(old), Some(new)) = (old.as_object(), new.as_object()) else {
        return vec!["the whole of them".to_owned()];
    };
    let mut keys: Vec<String> = old
        .keys()
        .chain(new.keys())
        .filter(|key| old.get(*key) != new.get(*key))
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// A task definition's inputs, with its containers read and the proxy container's guardian URLs taken out of them,
/// and those URLs.
fn split_urls(mut inputs: Value) -> Option<(Value, Urls)> {
    let mut containers: Value =
        serde_json::from_str(inputs.get("containerDefinitions")?.as_str()?).ok()?;
    let proxy = containers
        .as_array_mut()?
        .iter_mut()
        .find(|container| container.get("name") == Some(&Value::from("proxy")))?;
    let urls = Urls::of(proxy);
    let environment = proxy.get_mut("environment")?.as_array_mut()?;
    environment.retain(|entry| {
        !URL_KEYS
            .iter()
            .any(|key| entry.get("name") == Some(&Value::from(*key)))
    });
    environment.sort_by_key(|entry| {
        entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });
    inputs["containerDefinitions"] = containers;
    Some((inputs, urls))
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

/// The proxy's ECS service, settled on one deployment, and the task definition Pulumi's state records for it.
#[derive(PartialEq)]
struct Ecs {
    task_definition: String,
    image: String,
    urls: Urls,
    state_task_definition: String,
}

fn settled_service(ctx: &Ctx, dir: &str, stack: &Stack, region: &str) -> Result<Ecs> {
    let (counts, ecs) = running_service(ctx, dir, stack, region).with_context(|| {
        format!(
            "could not read the proxy service of stack {} from ECS",
            stack.name
        )
    })?;
    let [desired, running, deployments] = counts;
    if desired < 1 || running != desired || deployments != 1 {
        bail!(
            "the proxy service runs {running} of {desired} tasks in {deployments} deployments; wait for it to settle, or bring it back with a refreshed pulumi up of the proxy stack, then run this step again"
        );
    }
    Ok(ecs)
}

/// The service's desired and running task counts and its number of deployments, and its primary deployment.
fn running_service(ctx: &Ctx, dir: &str, stack: &Stack, region: &str) -> Result<([u64; 3], Ecs)> {
    let resources = export(ctx, dir, &stack.name)?.deployment.resources;
    let service = resources
        .iter()
        .find(|resource| resource.kind == "aws:ecs/service:Service")
        .and_then(|resource| resource.outputs.as_ref())
        .context("the proxy stack's state has no ECS service")?;
    let live: Vec<&str> = resources
        .iter()
        .filter(|resource| {
            resource.kind == "aws:ecs/taskDefinition:TaskDefinition" && !resource.delete
        })
        .filter_map(|resource| resource.outputs.as_ref()?.get("arn")?.as_str())
        .collect();
    let [state_task_definition] = live[..] else {
        bail!(
            "the proxy stack's state records {} live task definitions, not one",
            live.len()
        );
    };
    let field = |key: &str| {
        service
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .with_context(|| format!("the proxy's ECS service has no {key}"))
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
    let container: Value = read_json(
        ctx.exec,
        &Cmd::new("aws")
            .args(["ecs", "describe-task-definition", "--region", region])
            .args(["--task-definition", task_definition])
            .args([
                "--query",
                "taskDefinition.containerDefinitions[?name==`proxy`] | [0]",
                "--output",
                "json",
            ]),
    )?;
    let image = container
        .get("image")
        .and_then(Value::as_str)
        .with_context(|| format!("ECS's task definition {task_definition} has no proxy container"))?
        .to_owned();
    let count = |value: &str| {
        value
            .parse::<u64>()
            .with_context(|| format!("ECS reported {value} as a count"))
    };
    Ok((
        [count(desired)?, count(running)?, count(deployments)?],
        Ecs {
            task_definition: task_definition.to_owned(),
            image,
            urls: Urls::of(&container),
            state_task_definition: state_task_definition.to_owned(),
        },
    ))
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use super::*;

    const TASK: &str = "urn:pulumi:testnet::proxy::aws:ecs/taskDefinition:TaskDefinition::t";
    const SERVICE_URN: &str = "urn:pulumi:testnet::proxy::aws:ecs/service:Service::s";

    /// The proxy container, as ECS describes it.
    pub fn container(backend: &str, standby: Option<&str>, image: &str) -> Value {
        let mut environment = vec![
            json!({ "name": "GUARDIAN_BACKEND_URL", "value": backend }),
            json!({ "name": "SUI_RPC_URL", "value": "https://fullnode.testnet.sui.io:443" }),
        ];
        if let Some(standby) = standby {
            environment.push(json!({ "name": "STANDBY_GUARDIAN_URL", "value": standby }));
        }
        json!({ "name": "proxy", "image": image, "environment": environment })
    }

    /// A task definition's inputs, as a preview shows them: its containers are a JSON string.
    pub fn task(backend: &str, standby: Option<&str>, image: &str) -> Value {
        json!({
            "cpu": "256",
            "family": "proxy",
            "containerDefinitions": json!([container(backend, standby, image)]).to_string(),
        })
    }

    /// A preview of the proxy stack that replaces its task definition, `old`, with `new`.
    pub fn proxy_plan(old: Value, new: Value) -> Value {
        let service =
            |task: &str| json!({ "inputs": { "desiredCount": 1, "taskDefinition": task } });
        json!({
            "steps": [
                { "op": "replace", "urn": TASK, "oldState": { "inputs": old }, "newState": { "inputs": new } },
                {
                    "op": "update",
                    "urn": SERVICE_URN,
                    "oldState": service("arn:aws:ecs:us-west-2:1:task-definition/proxy:7"),
                    "newState": service("04da6b54-80e4-46f7-96ec-b56ff0331ba9"),
                },
                { "op": "read", "urn": "urn:pulumi:testnet::proxy::pulumi:pulumi:StackReference::org/enclave/testnet" },
            ],
            "changeSummary": {},
        })
    }

    fn plan(value: Value) -> Plan {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn finds_the_guardian_urls_a_plan_sets() {
        let old = task("http://192.0.2.1:3000", None, "repo:tag");
        let new = task(
            "http://192.0.2.1:3000",
            Some("http://192.0.2.2:3000"),
            "repo:tag",
        );
        let plan = plan(proxy_plan(old, new));
        let urls = guardian_urls(&plan).unwrap();
        assert_eq!(
            urls,
            Urls {
                backend: "http://192.0.2.1:3000".to_owned(),
                standby: Some("http://192.0.2.2:3000".to_owned()),
            }
        );
        assert_eq!(urls.relay(), "http://192.0.2.2:3000");
        assert!(plan.changes().iter().all(follows_slots));
    }

    #[test]
    fn refuses_a_plan_that_changes_anything_else() {
        let old = || task("http://192.0.2.1:3000", None, "repo:tag");
        let error = |plan: Value| guardian_urls(&self::plan(plan)).unwrap_err().to_string();
        let image = task("http://192.0.2.1:3000", None, "repo:other");
        assert!(error(proxy_plan(old(), image)).contains("by more than its guardian URLs"));
        let mut cpu = task("http://192.0.2.2:3000", None, "repo:tag");
        cpu["cpu"] = "512".into();
        assert!(error(proxy_plan(old(), cpu)).contains("by more than its guardian URLs"));
        // Every container counts, not only the proxy's.
        let mut sidecar = task("http://192.0.2.2:3000", None, "repo:tag");
        sidecar["containerDefinitions"] = json!([
            container("http://192.0.2.2:3000", None, "repo:tag"),
            { "name": "sidecar", "image": "sidecar:2" },
        ])
        .to_string()
        .into();
        assert!(error(proxy_plan(old(), sidecar)).contains("by more than its guardian URLs"));

        let new = task("http://192.0.2.2:3000", None, "repo:tag");
        let mut scaled = proxy_plan(old(), new.clone());
        scaled["steps"][1]["newState"]["inputs"]["desiredCount"] = 2.into();
        assert!(error(scaled).contains("service by more than its task definition"));
        let mut unread = proxy_plan(old(), new);
        unread["steps"][1]
            .as_object_mut()
            .unwrap()
            .remove("newState");
        assert!(error(unread).contains("no inputs this step can compare"));

        assert!(!follows_slots(&Change::new("delete", SERVICE_URN)));
        assert!(!follows_slots(&Change::new(
            "update",
            "urn:pulumi:testnet::proxy::aws:s3/bucketV2:BucketV2::other"
        )));
    }
}

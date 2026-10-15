// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The steps that write a slot's configuration: `render`.

use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::commit::Tree;
use crate::next;
use crate::render::SlotRender;
use crate::say;
use crate::stack::Slot;
use crate::steps::slot;
use crate::warn;

/// Writes the slot's configuration, then has the guardian's own tools load it as the ceremony will.
pub fn render(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "render")?;
    say(&format!(
        "Render slot {}'s guardian configuration",
        view.slot
    ));
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    let guardian_init = tree.guardian_init(ctx)?;
    let render = SlotRender::new(ctx, &stack, &view)?;
    std::fs::create_dir_all(&view.dir)?;
    render.rendered.write(&view.dir)?;
    if guardian_init.has_tool(ctx, "check-config")? {
        for config in render.rendered.configs() {
            let path = view.dir.join(config);
            // The configuration lists certificates relative to its own directory.
            let checked = ctx
                .exec
                .output(
                    &guardian_init
                        .cmd()
                        .args(["tools", "check-config", "--config"])
                        .arg(path.file_name().unwrap_or_default())
                        .cwd(path.parent().unwrap_or(&view.dir)),
                )?
                .success;
            if !checked {
                render.rendered.remove_operator_configs(&view.dir)?;
                bail!(
                    "The guardian's tools refuse {}, so no step will run with it. Fix what they name, then render again.",
                    path.display()
                );
            }
        }
    } else {
        warn(
            "This guardian's build has no tools check-config, so its tools have not checked the rendered files.",
        );
    }

    let settings = &render.settings;
    println!("Guardian commit:  {}", settings.commit);
    println!("PCR0:             {}", settings.pcr0);
    println!("Log bucket:       s3://{}", settings.bucket);
    println!("Bitcoin network:  {}", settings.bitcoin_network);
    println!("Retention class:  {}", settings.retention_environment);
    let dir = view.dir.display();
    match &render.new {
        Some(new) => {
            println!(
                "KP-set rotation:  {} key provisioners, any {} sign, re-deal to {}, any {} provision",
                render.dealt.kp_count(),
                render.dealt.threshold,
                new.kp_count(),
                new.threshold
            );
            println!("For the signers:      {dir}/rotate-kp-set/guardian-init.yaml");
            println!("For the re-deal:      {dir}/rotate-kp-set/operator.yaml");
        }
        None => println!(
            "Key provisioners: {}, any {} provision",
            render.dealt.kp_count(),
            render.dealt.threshold
        ),
    }
    println!("For key provisioners: {dir}/guardian-init.yaml");
    println!("For the operator:     {dir}/operator.yaml");
    next(&match render.new {
        Some(_) => format!("publish {} rotate-kp-set", view.slot),
        None => format!("publish {}", view.slot),
    });
    Ok(())
}

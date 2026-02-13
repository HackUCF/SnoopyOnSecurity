use log::*;
use rust_embed::Embed;
use yara_x::{Compiler, Rules};

#[derive(Embed)]
#[folder = "rules"]
#[include = "*.yar"]
struct YaraEmbed;

fn add_rules<EmbedFS: Embed>(cmp: &mut Compiler, name: &str) {
    let mut rules_added = 0;
    let mut rules_failed = 0;

    for file_name in EmbedFS::iter() {
        let ef = match EmbedFS::get(file_name.as_ref()) {
            Some(ef) => ef,
            None => {
                error!(
                    "{} - failed to get rule data for {}",
                    name,
                    file_name.as_ref()
                );
                rules_failed += 1;
                continue;
            }
        };

        match cmp.add_source(ef.data.as_ref()) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "{} - failed to load rule {} with error {}",
                    name,
                    file_name.as_ref(),
                    e
                );
                rules_failed += 1;
                continue;
            }
        }

        rules_added += 1;
        debug!("{} - successfully loaded rule {}", name, file_name);
    }

    if rules_failed != 0 {
        warn!("{} - {} yara rules failed to load", name, rules_failed);
    }

    info!("{} - yara initialized with {} rules", name, rules_added);
}

pub fn compile_rules() -> Rules {
    let mut cmp: Compiler = Compiler::new();
    add_rules::<YaraEmbed>(&mut cmp, "my rules");
    return cmp.build();
}

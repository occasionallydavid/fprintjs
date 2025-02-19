use std::io::prelude::*;
use std::io::Read;

use clap::{Parser, Subcommand};
use log::*;
use tar::Archive;
use yara::Rules;


#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    //#[command(arg_required_else_help(true))]
    #[command(subcommand)]
    command: Commands,
}


#[derive(Subcommand)]
#[command(arg_required_else_help(true))]
enum Commands {
    TestOwnSamples,
    SmokeTest,
}


fn get_test_cases(rules: &Rules)
    -> Vec<(String, String)>
{
    let mut tests = vec![];

    for rule in rules.get_rules() {
        let sample_file = rule.metadatas
            .iter()
            .find(|md| md.identifier == "sample_file")
            .map(|md| match md.value {
                yara::MetadataValue::String(s) => Some(s),
                _ => None,
            })
            .flatten()
            .expect("Rule lacks sample_file metadata");


        tests.push((sample_file.to_string(), rule.identifier.to_string()));
    }

    tests
}


fn compile_rules() -> anyhow::Result<Rules>
{
    Ok(
        yara::Compiler::new()?
            .add_rules_file("rules.yar")?
            .compile_rules()?
    )
}


fn test_own_samples(rules: &Rules) -> anyhow::Result<()>
{
    for (path, expected_match) in get_test_cases(&rules) {
        let buf = std::fs::read(&path)?;

        let matched_rule_ids: Vec<_> = rules
            .scan_mem(&buf, buf.len() as i32)?
            .into_iter()
            .map(|r| r.identifier)
            .collect();

        if matched_rule_ids == &[expected_match.clone()] {
            info!("{} matched expected {}", path, expected_match);
        } else {
            error!("{} matched incorrect {:?}", path, matched_rule_ids);
        }
    }

    Ok(())
}


fn smoke_test(rules: &Rules) -> anyhow::Result<()>
{
    let file = std::fs::File::open(
        "samples/HynekPetrak__javascript-malware-collection-master.tar.zst"
    )?;
    let reader = zstd::stream::Decoder::new(file)?;

    let mut archive = Archive::new(reader);

    let mut fails = 0usize;
    let mut sample_count = 0usize;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();

        if !path.ends_with(".js") {
            continue;
        }

        info!("Testing against {}", path);
        sample_count += 1;

        let mut buf = vec![];
        entry.read_to_end(&mut buf)?;

        let matched_rule_ids: Vec<_> = rules
            .scan_mem(&buf, buf.len() as i32)?
            .into_iter()
            .map(|r| r.identifier)
            .collect();

        if !matched_rule_ids.is_empty() {
            error!("{} matched incorrect {:?}", path, matched_rule_ids);
            fails += 1;
        }
    }

    if fails > 0 {
        error!("{} false positives were found.", fails);
    } else {
        info!("0 false positives found in {} test samples.", sample_count);
    }

    Ok(())
}


fn main() -> anyhow::Result<()> {
    simple_logger::init().unwrap();

    let rules = compile_rules()?;

    let cli = Cli::parse();
    match &cli.command {
        Commands::TestOwnSamples => test_own_samples(&rules)?,
        Commands::SmokeTest => smoke_test(&rules)?,
    };

    Ok(())
}

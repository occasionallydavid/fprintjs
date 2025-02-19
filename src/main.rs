use log::*;


fn get_test_cases(rules: &yara::Rules)
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


fn main() {
    simple_logger::init().unwrap();

    let compiler = yara::Compiler::new().unwrap();
    let compiler = compiler
        .add_rules_file("rules.yar")
        .expect("Should have parsed rule");
    let rules = compiler
        .compile_rules()
        .expect("Should have compiled rules");

    for (path, expected_match) in get_test_cases(&rules) {
        let buf = std::fs::read(&path)
            .expect("Could not read input");

        let matched_rule_ids: Vec<_> = rules
            .scan_mem(&buf, buf.len() as i32)
            .expect("Should have scanned")
            .into_iter()
            .map(|r| r.identifier)
            .collect();

        if matched_rule_ids == &[expected_match.clone()] {
            info!("Success: {} matched expected {}", path, expected_match);
        } else {
            error!("Success: {} matched incorrect {:?}",
                   path, matched_rule_ids);
        }
    }
}

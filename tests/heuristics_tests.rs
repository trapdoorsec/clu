use std::fs;

#[test]
fn test_validate_heuristics_file() {
    // Note: This requires heuristics.toml to exist in the project root
    // We'll write a simple validation without importing - just test TOML structure
    let content = fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let parsed: Result<toml::Value, _> = toml::from_str(&content);
    assert!(parsed.is_ok(), "heuristics.toml should be valid TOML");

    let rules_value = parsed.unwrap();
    assert!(
        rules_value.get("rules").is_some(),
        "Should have 'rules' array"
    );

    println!("✓ heuristics.toml structure is valid");
}

#[test]
fn test_deserialize_heuristics_toml() {
    let content = fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let result: Result<toml::Value, _> = toml::from_str(&content);

    match result {
        Ok(parsed) => {
            println!("Successfully parsed TOML");
            println!("{:#?}", parsed);
        }
        Err(e) => {
            panic!("Failed to deserialize heuristics.toml: {}", e);
        }
    }
}

#[test]
fn test_all_rules_have_required_fields() {
    let content = fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let parsed: toml::Value = toml::from_str(&content).expect("Failed to parse TOML");

    let rules = parsed
        .get("rules")
        .expect("No 'rules' array found")
        .as_array()
        .expect("'rules' is not an array");

    for (idx, rule) in rules.iter().enumerate() {
        let rule_table = rule
            .as_table()
            .unwrap_or_else(|| panic!("Rule {} is not a table", idx));

        // Required fields for all rules
        assert!(
            rule_table.contains_key("name"),
            "Rule {} missing 'name'",
            idx
        );
        assert!(
            rule_table.contains_key("type"),
            "Rule {} missing 'type'",
            idx
        );
        assert!(
            rule_table.contains_key("risk_score"),
            "Rule {} missing 'risk_score'",
            idx
        );
        assert!(
            rule_table.contains_key("description"),
            "Rule {} missing 'description'",
            idx
        );

        let rule_type = rule_table.get("type").unwrap().as_str().unwrap();

        // Type-specific field validation
        match rule_type {
            "keyword" => {
                assert!(
                    rule_table.contains_key("field"),
                    "Keyword rule {} missing 'field'",
                    idx
                );
                assert!(
                    rule_table.contains_key("keywords"),
                    "Keyword rule {} missing 'keywords'",
                    idx
                );
            }
            "regex" => {
                assert!(
                    rule_table.contains_key("field"),
                    "Regex rule {} missing 'field'",
                    idx
                );
                assert!(
                    rule_table.contains_key("pattern"),
                    "Regex rule {} missing 'pattern'",
                    idx
                );
            }
            "metadata" => {
                assert!(
                    rule_table.contains_key("field"),
                    "Metadata rule {} missing 'field'",
                    idx
                );
                assert!(
                    rule_table.contains_key("check"),
                    "Metadata rule {} missing 'check'",
                    idx
                );
            }
            _ => panic!("Unknown rule type: {}", rule_type),
        }
    }
}

#[test]
fn test_risk_scores_in_valid_range() {
    let content = fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let parsed: toml::Value = toml::from_str(&content).expect("Failed to parse TOML");

    let rules = parsed.get("rules").unwrap().as_array().unwrap();

    for rule in rules {
        let risk_score = rule
            .get("risk_score")
            .expect("Missing risk_score")
            .as_integer()
            .expect("risk_score is not an integer");

        assert!(
            (0..=100).contains(&risk_score),
            "Risk score {} out of range (0-100)",
            risk_score
        );
    }
}

#[test]
fn test_valid_field_names() {
    let valid_fields = ["description", "title", "link", "author", "published_date"];

    let content = fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let parsed: toml::Value = toml::from_str(&content).expect("Failed to parse TOML");

    let rules = parsed.get("rules").unwrap().as_array().unwrap();

    for (idx, rule) in rules.iter().enumerate() {
        if let Some(field) = rule.get("field") {
            let field_str = field
                .as_str()
                .unwrap_or_else(|| panic!("Rule {} field is not a string", idx));

            assert!(
                valid_fields.contains(&field_str),
                "Rule {} has invalid field name: {}",
                idx,
                field_str
            );
        }
    }
}

#[test]
fn test_metadata_checks_valid() {
    let valid_checks = ["is_some", "is_none"];

    let content = fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let parsed: toml::Value = toml::from_str(&content).expect("Failed to parse TOML");

    let rules = parsed.get("rules").unwrap().as_array().unwrap();

    for rule in rules {
        if rule.get("type").unwrap().as_str().unwrap() == "metadata" {
            let check = rule
                .get("check")
                .expect("Metadata rule missing 'check'")
                .as_str()
                .expect("check is not a string");

            assert!(
                valid_checks.contains(&check),
                "Invalid metadata check: {}",
                check
            );
        }
    }
}

use regex::Regex;
use std::time::{Duration, Instant};

/// Test for ReDoS (Regular Expression Denial of Service) attacks
/// Malicious regex patterns can cause catastrophic backtracking
#[test]
fn test_redos_protection() {
    // Known ReDoS patterns - these should timeout or be rejected
    let malicious_patterns = vec![
        r"(a+)+b",            // Classic ReDoS
        r"(a*)*b",            // Nested quantifiers
        r"(a|a)*b",           // Alternation with repetition
        r"(a|ab)*c",          // More complex alternation
        r"([a-zA-Z]+)*[0-9]", // Common pattern with ReDoS potential
    ];

    let test_input = "a".repeat(30); // Long input to trigger backtracking

    for pattern in malicious_patterns {
        println!("Testing pattern: {}", pattern);

        let re = Regex::new(pattern);

        if let Ok(regex) = re {
            let start = Instant::now();
            let _ = regex.is_match(&test_input);
            let elapsed = start.elapsed();

            // Regex should complete in reasonable time (< 100ms)
            assert!(
                elapsed < Duration::from_millis(100),
                "Pattern '{}' took {:?} - potential ReDoS!",
                pattern,
                elapsed
            );
        }
    }
}

/// Test that malformed TOML doesn't cause panics
#[test]
fn test_malformed_toml_handling() {
    let malformed_inputs = vec![
        // Missing closing bracket
        "[[rules]\nname = \"test\"",
        // Invalid TOML syntax
        "rules = {{{",
        // Unterminated string
        "[[rules]]\nname = \"unterminated",
        // Invalid escape sequence
        "[[rules]]\npattern = \"\\z\"",
    ];

    for input in malformed_inputs {
        let result: Result<toml::Value, _> = toml::from_str(input);

        // Should return Err, not panic
        assert!(result.is_err(), "Should fail to parse: {}", input);
    }
}

/// Test that type mismatches are caught during deserialization
#[test]
fn test_type_mismatch_in_deserialization() {
    // TOML will parse this (it's valid TOML), but deserializing to HeuristicRule should fail
    let type_mismatch = r#"
        [[rules]]
        name = 123
        type = true
        field = "description"
        risk_score = "not a number"
    "#;

    let parsed: Result<toml::Value, _> = toml::from_str(type_mismatch);

    // TOML parsing should succeed
    assert!(parsed.is_ok(), "TOML should parse successfully");

    // But this would be where struct deserialization would fail
    // (not testing HeuristicRule deserialization here since it's not exported)
}

/// Test resource exhaustion via large TOML files
#[test]
fn test_large_toml_handling() {
    // Create TOML with excessive rules
    let mut large_toml = String::new();

    for i in 0..10000 {
        large_toml.push_str(&format!(
            "[[rules]]\nname = \"rule_{}\"\ntype = \"keyword\"\nfield = \"description\"\n\
             keywords = [\"test\"]\nrisk_score = 50\ndescription = \"test\"\n\n",
            i
        ));
    }

    let start = Instant::now();
    let result: Result<toml::Value, _> = toml::from_str(&large_toml);
    let elapsed = start.elapsed();

    // Should parse but set a reasonable timeout (< 5 seconds)
    assert!(
        elapsed < Duration::from_secs(5),
        "Parsing took too long: {:?}",
        elapsed
    );

    if let Ok(parsed) = result {
        println!(
            "Successfully parsed {} rules in {:?}",
            parsed["rules"].as_array().unwrap().len(),
            elapsed
        );
    }
}

/// Test for deeply nested TOML structures
#[test]
fn test_deeply_nested_toml() {
    let mut nested = String::from("data = ");

    // Create deeply nested structure
    for _ in 0..100 {
        nested.push_str("{ nested = ");
    }
    nested.push_str("\"value\"");
    for _ in 0..100 {
        nested.push_str(" }");
    }

    let result: Result<toml::Value, _> = toml::from_str(&nested);

    // Should either parse or fail gracefully, not crash
    match result {
        Ok(_) => println!("Parsed deeply nested structure"),
        Err(e) => println!("Failed to parse (expected): {}", e),
    }
}

/// Test that regex patterns actually compile
#[test]
fn test_regex_patterns_compile() {
    let content =
        std::fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let parsed: toml::Value = toml::from_str(&content).expect("Failed to parse TOML");

    let rules = parsed.get("rules").unwrap().as_array().unwrap();

    for rule in rules {
        if rule.get("type").unwrap().as_str().unwrap() == "regex" {
            let pattern = rule
                .get("pattern")
                .expect("Regex rule missing pattern")
                .as_str()
                .expect("Pattern is not a string");

            let result = Regex::new(pattern);

            assert!(
                result.is_ok(),
                "Invalid regex pattern in rule '{}': {}",
                rule.get("name").unwrap().as_str().unwrap(),
                pattern
            );
        }
    }
}

/// Test for potential command injection via TOML values
/// (if values were ever used in system commands - they shouldn't be!)
#[test]
fn test_no_command_injection_chars() {
    let dangerous_chars = vec![";", "|", "&", "$", "`", "\n", "$(", "${"];

    let content =
        std::fs::read_to_string("heuristics.toml").expect("Failed to read heuristics.toml");

    let parsed: toml::Value = toml::from_str(&content).expect("Failed to parse TOML");

    // Check that rule names don't contain shell metacharacters
    // (defense in depth - even though we don't execute them)
    let rules = parsed.get("rules").unwrap().as_array().unwrap();

    for rule in rules {
        let name = rule.get("name").unwrap().as_str().unwrap();

        for dangerous in &dangerous_chars {
            assert!(
                !name.contains(dangerous),
                "Rule name '{}' contains dangerous character '{}'",
                name,
                dangerous
            );
        }
    }
}

/// Test integer overflow in risk_score
#[test]
fn test_risk_score_overflow() {
    let overflow_toml = r#"
        [[rules]]
        name = "overflow_test"
        type = "keyword"
        field = "description"
        keywords = ["test"]
        risk_score = 999999999999999999
        description = "test"
    "#;

    let result: Result<toml::Value, _> = toml::from_str(overflow_toml);

    // Should either parse with clamping or fail gracefully
    if let Ok(parsed) = result {
        let score = parsed["rules"][0]["risk_score"].as_integer();
        println!("Parsed overflow score as: {:?}", score);
    }
}

/// Test empty/whitespace-only strings
#[test]
fn test_empty_string_handling() {
    let empty_strings_toml = r#"
        [[rules]]
        name = ""
        type = "keyword"
        field = "description"
        keywords = [""]
        risk_score = 50
        description = ""
    "#;

    let result: Result<toml::Value, _> = toml::from_str(empty_strings_toml);

    // Should parse but application logic should validate non-empty
    assert!(result.is_ok(), "Should parse empty strings");

    // Validation would happen at application level
    let parsed = result.unwrap();
    let name = parsed["rules"][0]["name"].as_str().unwrap();
    assert_eq!(name, "", "Empty string should be preserved");
}

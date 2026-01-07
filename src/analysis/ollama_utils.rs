/// Ollama utility functions for checking and pulling models
use std::error::Error;
use serde_json::json;

/// Check if model is available and optionally pull it
pub async fn check_model_available(
    url: &str,
    model_name: &str,
    auto_pull: bool,
) -> Result<(), Box<dyn Error>> {
    let tags_url = if url.ends_with('/') {
        format!("{}api/tags", url)
    } else {
        format!("{}/api/tags", url)
    };

    // Check if model exists
    match reqwest::get(&tags_url).await {
        Ok(response) if response.status().is_success() => {
            match response.json::<serde_json::Value>().await {
                Ok(json) => {
                    if let Some(models) = json.get("models").and_then(|v| v.as_array()) {
                        let model_exists = models.iter().any(|m| {
                            m.get("name")
                                .and_then(|n| n.as_str())
                                .map(|name| name.contains(model_name))
                                .unwrap_or(false)
                        });

                        if model_exists {
                            log::debug!("Ollama: Model '{}' is available", model_name);
                            return Ok(());
                        }
                    }
                }
                Err(_) => {}
            }
        }
        _ => {}
    }

    // Model not found
    if !auto_pull {
        log::warn!("Ollama: Model '{}' not found at {}", model_name, url);
        eprintln!("       You can pull it with: ollama pull {} (from Ollama service)", model_name);
        return Ok(()); // Don't fail
    }

    // Try to auto-pull the model via HTTP API
    log::info!("Ollama: Model '{}' not found, attempting to pull via API...", model_name);

    let pull_url = if url.ends_with('/') {
        format!("{}api/pull", url)
    } else {
        format!("{}/api/pull", url)
    };

    let pull_request = json!({
        "name": model_name,
        "stream": false
    });

    match reqwest::Client::new()
        .post(&pull_url)
        .json(&pull_request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            log::info!("Ollama: Successfully initiated model pull for '{}'", model_name);
            // Wait a moment for the pull to complete
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            Ok(())
        }
        Ok(response) => {
            let status = response.status();
            log::warn!("Ollama: Failed to pull model '{}': HTTP {}", model_name, status);
            Ok(()) // Don't fail - model might pull in background
        }
        Err(e) => {
            log::warn!("Ollama: Could not initiate model pull: {}", e);
            Ok(()) // Don't fail - user can pull manually or it may retry
        }
    }
}

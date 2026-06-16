use serde_json::json;
/// Ollama utility functions for checking and pulling models
use std::error::Error;
use std::time::Duration;

const OLLAMA_TIMEOUT_SECS: u64 = 30;

fn build_client() -> Result<reqwest::Client, Box<dyn Error>> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(OLLAMA_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("Failed to build HTTP client for Ollama: {}", e).into())
}

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

    let client = build_client()?;

    match client.get(&tags_url).send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(json) = response.json::<serde_json::Value>().await
                && let Some(models) = json.get("models").and_then(|v| v.as_array())
            {
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
        _ => {}
    }

    if !auto_pull {
        log::warn!("Ollama: Model '{}' not found at {}", model_name, url);
        eprintln!(
            "       You can pull it with: ollama pull {} (from Ollama service)",
            model_name
        );
        return Ok(());
    }

    log::info!(
        "Ollama: Model '{}' not found, attempting to pull via API...",
        model_name
    );

    let pull_url = if url.ends_with('/') {
        format!("{}api/pull", url)
    } else {
        format!("{}/api/pull", url)
    };

    let pull_request = json!({
        "name": model_name,
        "stream": false
    });

    let pull_client = build_client()?;

    match pull_client
        .post(&pull_url)
        .json(&pull_request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            log::info!(
                "Ollama: Successfully initiated model pull for '{}'",
                model_name
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(())
        }
        Ok(response) => {
            let status = response.status();
            log::warn!(
                "Ollama: Failed to pull model '{}': HTTP {}",
                model_name,
                status
            );
            Ok(())
        }
        Err(e) => {
            log::warn!("Ollama: Could not initiate model pull: {}", e);
            Ok(())
        }
    }
}
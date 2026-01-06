#![allow(dead_code)]

pub mod pypi;
use pypi::PythonPackage;
use rss::Channel;
use std::error::Error;
use url::Url;

pub async fn fetch_rss(url: &Url) -> Result<Channel, Box<dyn Error>> {
    let xml = reqwest::get(url.as_str()).await?.bytes().await?;
    let channel = Channel::read_from(&xml[..])?;
    Ok(channel)
}

/// Extract package name from PyPI RSS title
/// Format: "packageName added to PyPI" or "packageName updated on PyPI"
fn extract_package_name(title: &str) -> String {
    // Split on common PyPI RSS patterns
    if let Some(pos) = title.find(" added to PyPI") {
        title[..pos].trim().to_string()
    } else if let Some(pos) = title.find(" updated on PyPI") {
        title[..pos].trim().to_string()
    } else if let Some(pos) = title.find(" added to") {
        title[..pos].trim().to_string()
    } else if let Some(pos) = title.find(" updated") {
        title[..pos].trim().to_string()
    } else {
        // Fallback: use as-is if format is unexpected
        title.trim().to_string()
    }
}

pub async fn serialize_packages(channel: Channel) -> Option<Vec<PythonPackage>> {
    let mut packages = Vec::new();
    for i in channel.items {
        let i_clone = i.clone();
        // Parse title to extract just the package name
        let parsed_title = i_clone.title.as_ref().map(|t| extract_package_name(t));
        let p = PythonPackage {
            title: parsed_title,
            link: i_clone.link,
            description: i.description().map(|s| s.to_string()),
            author: i.author().map(|s| s.to_string()),
            published_date: i.pub_date().map(|s| s.to_string()),
        };
        packages.push(p);
    }
    Some(packages)
}

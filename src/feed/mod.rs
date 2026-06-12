#![allow(dead_code)]

pub mod ecosystem;
pub mod npm;
pub mod pypi;

use pypi::PythonPackage;
use rss::Channel;
use std::error::Error;
use url::Url;

pub async fn fetch_rss(url: &Url) -> Result<Channel, Box<dyn Error>> {
    fetch_rss_raw(url).await
}

pub async fn fetch_rss_raw(url: &Url) -> Result<Channel, Box<dyn Error>> {
    let xml = reqwest::get(url.as_str()).await?.bytes().await?;
    let channel = Channel::read_from(&xml[..])?;
    Ok(channel)
}

/// Extract package name from PyPI RSS title
/// Format: "packageName added to PyPI" or "packageName updated on PyPI"
fn extract_package_name(title: &str) -> String {
    if let Some(pos) = title.find(" added to PyPI") {
        title[..pos].trim().to_string()
    } else if let Some(pos) = title.find(" updated on PyPI") {
        title[..pos].trim().to_string()
    } else if let Some(pos) = title.find(" added to") {
        title[..pos].trim().to_string()
    } else if let Some(pos) = title.find(" updated") {
        title[..pos].trim().to_string()
    } else {
        title.trim().to_string()
    }
}

pub fn serialize_packages(channel: Channel) -> Vec<PythonPackage> {
    let mut packages = Vec::new();
    for item in channel.items {
        let parsed_title = item.title.as_ref().map(|t| extract_package_name(t));
        let description = item.description().map(|s| s.to_string());
        let author = item.author().map(|s| s.to_string());
        let published_date = item.pub_date().map(|s| s.to_string());
        let p = PythonPackage {
            title: parsed_title,
            link: item.link,
            description,
            author,
            published_date,
        };
        packages.push(p);
    }
    packages
}

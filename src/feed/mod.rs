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

pub async fn serialize_packages(channel: Channel) -> Option<Vec<PythonPackage>> {
    let mut packages = Vec::new();
    for i in channel.items {
        let i_clone = i.clone();
        let p = PythonPackage {
            title: i_clone.title,
            link: i_clone.link,
            description: i.description().map(|s| s.to_string()),
            author: i.author().map(|s| s.to_string()),
            published_date: i.pub_date().map(|s| s.to_string()),
        };
        packages.push(p);
    }
    Some(packages)
}

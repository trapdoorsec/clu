use package::PythonPackage;
use reqwest;
use rss::Channel;
use std::error::Error;
use url::Url;

async fn fetch_rss(url: &Url) -> Result<Channel, Box<dyn Error>> {
    let xml = reqwest::get(url.as_str()).await?.bytes().await?;
    let channel = Channel::read_from(&xml[..])?;
    Ok(channel)
}

async fn serialize_packages(channel: Channel) -> Option<Vec<PythonPackage>> {
    let packages = Vec::new();
    for i in channel.items {
        let p = PythonPackage {
            title: i.title.expect("No title in package"),
            link: i.link.expect("No link in package"),
            description: i.description().expect("No description set"),
            author: i.author(),
            published_date: i.pub_date().expect("No published date"),
        };
        packages.append(p);
    }
    Some(packages)
}

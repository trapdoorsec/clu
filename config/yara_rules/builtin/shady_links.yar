rule shady_links
{
    meta:
        severity = "medium"
        description = "Detects URLs to suspicious domains, obscure TLDs, IP addresses, URL shorteners, and tunnel services"
        ecosystem = "all"
        risk_score = 50
    strings:
        $shortener = /https?:\/\/(t\.co|bit\.ly|tinyurl\.com|is\.gd|vzturl\.com|ow\.ly|buff\.ly|rb\.gy)\// nocase
        $tunnel = /https?:\/\/[a-z0-9\-]+\.(ngrok\.io|serveo\.net|localtunnel\.me|pagekite\.me)\// nocase
        $suspicious_tld = /https?:\/\/[a-z0-9\-]+\.(tk|ml|ga|cf|gq|xyz|top|buzz|info|club|work|icu)\// nocase
        $raw_ip = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase
        $pastebin = /https?:\/\/(pastebin\.com|pasted\.co|hastebin\.com)\// nocase
        $discord_cdn = /https?:\/\/cdn\.discordapp\.com\/attachments\// nocase
        $github_raw = /https?:\/\/raw\.githubusercontent\.com\// nocase
    condition:
        any of them
}
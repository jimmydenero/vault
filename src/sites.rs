//! Which site a login belongs to, and whether a page is on it. Plain functions, no I/O.
//!
//! A login is tied to its site's registrable domain, as R7 ties an API key to its host: the
//! domain a person can register, one label below a public suffix, from the Public Suffix List
//! compiled into the `psl` crate. So `accounts.shopify.com` and `shopify.com` are one site, while
//! `alice.github.io` and `bob.github.io` are two, because `github.io` is a public suffix. A login
//! is filled only into an `https:` page on its own site (R5).

use url::{Host, Url};

use crate::error::VaultError;

/// The registrable domain of a host name: lower case, ASCII (punycode). `None` for an IP
/// address, a single label (`localhost`), or a name that is itself a public suffix (`co.uk`).
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    let domain = psl::domain_str(&host)?;
    (!domain.is_empty()).then(|| domain.to_string())
}

/// The host a login's `site` names. People type a site as `shopify.com`, `accounts.shopify.com`
/// or `https://shopify.com/login`; all three name the host before any path.
pub fn site_host(site: &str) -> Option<String> {
    let site = site.trim();
    let url = if site.contains("://") { Url::parse(site).ok()? } else { Url::parse(&format!("https://{site}")).ok()? };
    match url.host()? {
        Host::Domain(domain) => Some(domain.trim_end_matches('.').to_ascii_lowercase()),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

/// The registrable domain a login's `site` belongs to, or why it has none.
pub fn login_domain(site: &str) -> Result<String, VaultError> {
    site_host(site)
        .and_then(|host| registrable_domain(&host))
        .ok_or_else(|| VaultError::SiteMismatch(format!("the login's site {site:?} isn't a web domain")))
}

/// Checks that `url`, a page's or a frame's address, is `https:` and on `domain`. `what` names
/// the page in the refusal ("the tab", "the password field's page").
pub fn check_page(url: &str, domain: &str, what: &str) -> Result<(), VaultError> {
    let shown = shown_url(url);
    let parsed = Url::parse(url).map_err(|_| VaultError::SiteMismatch(format!("{what} has no web address ({shown})")))?;
    if parsed.scheme() != "https" {
        return Err(VaultError::SiteMismatch(format!("{what} isn't an https page ({shown})")));
    }
    let page_domain = match parsed.host() {
        Some(Host::Domain(host)) => registrable_domain(host),
        _ => None,
    };
    match page_domain {
        Some(page_domain) if page_domain == domain => Ok(()),
        Some(page_domain) => Err(VaultError::SiteMismatch(format!("{what} is on {page_domain}, not {domain}"))),
        None => Err(VaultError::SiteMismatch(format!("{what} isn't on a web domain ({shown})"))),
    }
}

/// An address as a refusal may show it: scheme, host and path, never a query or fragment (a
/// query can carry a token), at most 120 characters.
pub fn shown_url(url: &str) -> String {
    let cut = url.split(['?', '#']).next().unwrap_or("");
    cut.chars().filter(|c| !c.is_control()).take(120).collect()
}

/// A login's site as `generate-login` stores it: the host it names, lower case. Refused unless
/// it has a registrable domain, so every generated login can be filled.
pub fn normalize_new_site(site: &str) -> Result<String, VaultError> {
    let host = site_host(site)
        .ok_or_else(|| VaultError::InvalidSecret(format!("the site {site:?} isn't a web domain")))?;
    registrable_domain(&host)
        .ok_or_else(|| VaultError::InvalidSecret(format!("the site {site:?} has no registrable domain")))?;
    Ok(host)
}

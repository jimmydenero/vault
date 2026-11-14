//! `fill`: the vault types a saved login into the agent browser itself, so the password never
//! passes through the model or through the program that drives the browser (R5, owner's decision
//! of 2026-11-14). The browser is Chrome for Testing, run by the Volgenic host daemon on the same
//! machine. The daemon names a DevTools port on 127.0.0.1, a tab and the two fields. The vault
//! checks the page, writes the audit line, types the values and reports only what it filled (R4).
//!
//! The decisions are the plain functions at the top: `check_request` and `check_field`. The
//! rest is the shell that asks the browser and types.
//!
//! What a fill checks, in order. A failed check types nothing:
//! 1. The login exists and is a login (`no_such_login`).
//! 2. `expect_site`, the site the daemon believes the page is on, is the login's site, by
//!    registrable domain (`site_mismatch`). See `sites`.
//! 3. The port's listener is a program of the owner's own user ID (`browser_unreachable`), so
//!    another user on the machine can't stand in for the browser.
//! 4. The tab is an `https:` page on the login's site, from Chrome's own record of it
//!    (`Target.getTargetInfo`). So is a cross-origin frame's target, when one is named.
//! 5. Each field is found in the tab's frames, each frame searched in an isolated world of its
//!    own, where the page's scripts can't change what `tagName`, `type` or `document.URL` say. The
//!    field's own document must be `https:` and on the login's site too (`site_mismatch`), so a
//!    page can't frame another site's form, or put a field of its own in an ad's frame. The
//!    password goes only into an `<input type=password>`, the username only into a text, email
//!    or tel `<input>`, and both must be in one document (`not_a_password_field`).
//! 6. The audit line is written (R28). No line, no fill.
//! 7. For each field: `DOM.focus`, then, in the isolated world, select what the field holds and
//!    check that it is still connected, focused and on the site. Then `Input.insertText` through
//!    the tab. The text replaces the selection.

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use crate::devtools::{CdpError, DevTools};
use crate::error::VaultError;
use crate::model::{Kind, Record};
use crate::sites;

/// The longest a fill takes, from the first connection to the last character typed.
const FILL_DEADLINE: Duration = Duration::from_secs(20);
const WORLD: &str = "volgenic-vault";

/// A fill as the socket carries it, names aside.
#[derive(Clone, Debug)]
pub struct FillRequest {
    /// A DevTools port on 127.0.0.1. Never another host: there is no field for one.
    pub port: u16,
    /// The tab: a `page` target.
    pub target_id: String,
    /// The target the field nodes belong to, when they are in a cross-origin frame with its own
    /// target. Absent: the tab's.
    pub frame_target_id: Option<String>,
    /// `backendNodeId`s, in the session of `frame_target_id` or else the tab.
    pub username: Option<u64>,
    pub password: Option<u64>,
    pub expect_site: String,
}

/// What a fill typed. Names of fields only, never what went into them (R4).
pub struct Filled {
    pub filled: Vec<&'static str>,
}

/// What the audit line written before typing records (R28): the page's host and the browser.
pub struct FillStart<'a> {
    pub page_host: &'a str,
    pub browser: &'a str,
    pub fields: &'a [&'static str],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Username,
    Password,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Username => "username",
            Role::Password => "password",
        }
    }
}

/// What the isolated world reports about a node (`PROBE`).
#[derive(Deserialize, Debug)]
pub struct FieldProbe {
    /// Whether the node is in this world's own document.
    pub mine: bool,
    pub tag: String,
    /// `type` of an `<input>`, as the browser resolves it (`text` for a missing or unknown one).
    pub input_type: Option<String>,
    pub connected: bool,
    pub disabled: bool,
    pub read_only: bool,
    /// The node's own document's address.
    pub url: String,
}

/// Target ids are Chrome's: 32 hex digits today. Accept any short run of letters and digits.
fn valid_target_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

/// The checks that need no browser: the request's shape, the login, and `expect_site` against
/// the login's site. Returns the login's registrable domain.
pub(crate) fn check_request(request: &FillRequest, record: Option<&Record>, label: &str) -> Result<String, VaultError> {
    let record = match record {
        Some(record) if record.kind == Kind::Login => record,
        _ => return Err(VaultError::NoSuchLogin(label.to_string())),
    };
    if request.port == 0 {
        return Err(VaultError::BadRequest("cdp.port is a TCP port, 1 to 65535".into()));
    }
    if !valid_target_id(&request.target_id) || request.frame_target_id.as_deref().is_some_and(|id| !valid_target_id(id)) {
        return Err(VaultError::BadRequest("a target id is 1 to 64 letters and digits".into()));
    }
    if request.username.is_none() && request.password.is_none() {
        return Err(VaultError::BadRequest("fields names a username or a password node, or both".into()));
    }
    if request.username.is_some() && request.username == request.password {
        return Err(VaultError::NotAPasswordField("the username and password are the same node".into()));
    }
    let domain = sites::login_domain(&record.site)?;
    let expected = sites::site_host(&request.expect_site)
        .and_then(|host| sites::registrable_domain(&host))
        .ok_or_else(|| VaultError::SiteMismatch(format!("expect_site {:?} isn't a web domain", request.expect_site)))?;
    if expected != domain {
        return Err(VaultError::SiteMismatch(format!("the login is for {domain}, and the page was expected on {expected}")));
    }
    Ok(domain)
}

/// Whether a node may take a login's `role`, and is on the login's site.
pub fn check_field(role: Role, node: u64, probe: &FieldProbe, domain: &str) -> Result<(), VaultError> {
    if !probe.connected {
        return Err(VaultError::FieldNotFound(format!("node {node} is no longer on the page: read the page again")));
    }
    let input_type = probe.input_type.as_deref().map(str::to_ascii_lowercase);
    let fits = probe.tag.eq_ignore_ascii_case("input")
        && match role {
            Role::Password => input_type.as_deref() == Some("password"),
            Role::Username => matches!(input_type.as_deref(), Some("text" | "email" | "tel")),
        };
    if !fits {
        let wanted = match role {
            Role::Password => "an <input type=password>",
            Role::Username => "a text, email or tel <input>",
        };
        let found = match &input_type {
            Some(t) => format!("<input type={t}>"),
            None => format!("<{}>", probe.tag.to_ascii_lowercase().chars().take(30).collect::<String>()),
        };
        return Err(VaultError::NotAPasswordField(format!(
            "the {} field must be {wanted}; node {node} is {found}",
            role.label()
        )));
    }
    if probe.disabled || probe.read_only {
        return Err(VaultError::FieldNotFound(format!("node {node} is disabled or read-only")));
    }
    sites::check_page(&probe.url, domain, &format!("the {} field's page", role.label()))
}

/// Run on a node in an isolated world: what it is, and whether it belongs to this world's frame.
const PROBE: &str = r#"function () {
  const doc = this.ownerDocument;
  const input = this instanceof HTMLInputElement;
  return {
    mine: doc === document,
    tag: String(this.tagName || this.nodeName || ''),
    input_type: input ? String(this.type) : null,
    connected: this.isConnected === true,
    disabled: input && this.disabled === true,
    read_only: input && this.readOnly === true,
    url: doc ? String(doc.URL) : ''
  };
}"#;

/// Run just before typing: select what the field holds, so the typed text replaces it, and say
/// whether the field is still the focused, connected element of its document, and where.
const SELECT: &str = r#"function () {
  const doc = this.ownerDocument;
  if (typeof this.select === 'function') this.select();
  return { focused: this.isConnected === true && doc.activeElement === this, url: String(doc.URL) };
}"#;

#[derive(Deserialize)]
struct Selected {
    focused: bool,
    url: String,
}

/// A field found in its frame.
struct Located {
    node: u64,
    role: Role,
    frame_id: String,
    context: i64,
}

fn unreachable(why: impl Into<String>) -> VaultError {
    VaultError::BrowserUnreachable(why.into())
}

fn from_cdp(error: CdpError) -> VaultError {
    match error {
        CdpError::Transport(why) => VaultError::BrowserUnreachable(why),
        // Chrome's own message stays out of replies; the caller says what the step was.
        CdpError::Command(_) => VaultError::BrowserUnreachable("the browser refused a DevTools command".into()),
    }
}

/// Checks the listener, connects, and checks the tab and the fields (steps 3 to 5). Then calls
/// `record_use` (step 6), and types (step 7). `domain` is from `check_request`.
pub(crate) fn fill(
    record: &Record,
    request: &FillRequest,
    domain: &str,
    owner_uid: u32,
    record_use: &mut dyn FnMut(&FillStart) -> Result<(), VaultError>,
) -> Result<Filled, VaultError> {
    let port = request.port;
    match crate::platform::tcp_listener_uids(port) {
        None => return Err(unreachable("the vault couldn't check who listens on the DevTools port")),
        Some(uids) if uids.is_empty() => {
            return Err(unreachable(format!("no program of yours is listening on 127.0.0.1:{port}")));
        }
        Some(uids) if uids.iter().any(|uid| *uid != owner_uid) => {
            return Err(unreachable(format!("127.0.0.1:{port} is held by another user's program")));
        }
        Some(_) => {}
    }
    let deadline = Instant::now() + FILL_DEADLINE;
    let mut cdp = DevTools::connect(port, deadline).map_err(from_cdp)?;

    // Step 4: the tab, and the frame target if one is named, from Chrome's own records.
    let tab_url = target_url(&mut cdp, &request.target_id, "page")?;
    sites::check_page(&tab_url, domain, "the tab")?;
    let page_host = url::Url::parse(&tab_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let tab_session = attach(&mut cdp, &request.target_id)?;
    let node_session = match &request.frame_target_id {
        Some(frame_target) => {
            let frame_url = target_url(&mut cdp, frame_target, "iframe")?;
            sites::check_page(&frame_url, domain, "the frame")?;
            attach(&mut cdp, frame_target)?
        }
        None => tab_session.clone(),
    };

    // Step 5: find each field's frame and check it.
    let frames = frame_list(&mut cdp, &node_session)?;
    let mut located = Vec::new();
    for (role, node) in [(Role::Username, request.username), (Role::Password, request.password)] {
        let Some(node) = node else { continue };
        located.push(locate(&mut cdp, &node_session, &frames, role, node, domain)?);
    }
    if let [first, second] = &located[..] {
        if first.frame_id != second.frame_id {
            return Err(VaultError::NotAPasswordField("the username and password fields are in different frames".into()));
        }
    }
    // The browser's own record of the form's frame must agree with what the document said.
    for frame in located.iter().map(|l| &l.frame_id) {
        let url = frames.iter().find(|(id, _)| id == frame).map(|(_, url)| url.as_str()).unwrap_or("");
        sites::check_page(url, domain, "the login form's frame")?;
    }

    // Step 6 (R28).
    let fields: Vec<&'static str> = located.iter().map(|l| l.role.label()).collect();
    let browser = cdp.browser.clone();
    record_use(&FillStart { page_host: &page_host, browser: &browser, fields: &fields })?;

    // Step 7.
    let mut filled = Vec::new();
    for field in &located {
        cdp.call("DOM.focus", json!({ "backendNodeId": field.node }), Some(&node_session))
            .map_err(|_| VaultError::FieldNotFound(format!("node {} couldn't be focused", field.node)))?;
        let selected: Selected = call_on(&mut cdp, &node_session, field.node, field.context, SELECT)?;
        if !selected.focused {
            return Err(VaultError::FieldNotFound(format!(
                "node {} didn't keep the focus{}",
                field.node,
                if filled.is_empty() { ", so nothing was typed" } else { "" }
            )));
        }
        sites::check_page(&selected.url, domain, &format!("the {} field's page", field.role.label()))?;
        match field.role {
            Role::Username => {
                let username = record.username.as_deref().unwrap_or("");
                cdp.call("Input.insertText", json!({ "text": username }), Some(&tab_session)).map_err(from_cdp)?;
            }
            Role::Password => {
                // R1: the fill's call site of `expose`. The value goes from the vault's memory
                // into one wiped message buffer, and from there only to the browser.
                let password = std::str::from_utf8(record.value.expose())
                    .map_err(|_| VaultError::InvalidSecret("this login's password isn't text".into()))?;
                cdp.insert_secret_text(&tab_session, password).map_err(from_cdp)?;
            }
        }
        filled.push(field.role.label());
    }
    for session in [&node_session, &tab_session] {
        let _ = cdp.call("Target.detachFromTarget", json!({ "sessionId": session }), None);
    }
    Ok(Filled { filled })
}

/// A target's address from Chrome's own records, checking its type (`page` or `iframe`).
fn target_url(cdp: &mut DevTools, target_id: &str, kind: &str) -> Result<String, VaultError> {
    let info = cdp
        .call("Target.getTargetInfo", json!({ "targetId": target_id }), None)
        .map_err(|_| unreachable(format!("the browser has no target {target_id}")))?;
    let info = &info["targetInfo"];
    if info["type"].as_str() != Some(kind) {
        return Err(unreachable(format!("target {target_id} isn't a {}", if kind == "page" { "tab" } else { "frame" })));
    }
    Ok(info["url"].as_str().unwrap_or("").to_string())
}

fn attach(cdp: &mut DevTools, target_id: &str) -> Result<String, VaultError> {
    let attached = cdp
        .call("Target.attachToTarget", json!({ "targetId": target_id, "flatten": true }), None)
        .map_err(|_| unreachable(format!("couldn't attach to target {target_id}")))?;
    attached["sessionId"].as_str().map(str::to_string).ok_or_else(|| unreachable("no DevTools session"))
}

/// Every frame in the session's frame tree, the main frame first: id and address, from the
/// browser's own records.
fn frame_list(cdp: &mut DevTools, session: &str) -> Result<Vec<(String, String)>, VaultError> {
    let tree = cdp.call("Page.getFrameTree", json!({}), Some(session)).map_err(from_cdp)?;
    let mut frames = Vec::new();
    let mut stack = vec![&tree["frameTree"]];
    while let Some(node) = stack.pop() {
        if let (Some(id), Some(url)) = (node["frame"]["id"].as_str(), node["frame"]["url"].as_str()) {
            frames.push((id.to_string(), url.to_string()));
        }
        if let Some(children) = node["childFrames"].as_array() {
            stack.extend(children.iter().rev());
        }
        if frames.len() > 200 {
            break;
        }
    }
    if frames.is_empty() {
        return Err(unreachable("the tab has no frames"));
    }
    Ok(frames)
}

/// Finds the frame whose document holds `node`, probing it in one isolated world per frame.
fn locate(
    cdp: &mut DevTools,
    session: &str,
    frames: &[(String, String)],
    role: Role,
    node: u64,
    domain: &str,
) -> Result<Located, VaultError> {
    for (frame_id, _) in frames {
        let world = cdp.call(
            "Page.createIsolatedWorld",
            json!({ "frameId": frame_id, "worldName": WORLD, "grantUniveralAccess": false }),
            Some(session),
        );
        let Some(context) = world.ok().and_then(|w| w["executionContextId"].as_i64()) else { continue };
        let probe: FieldProbe = match call_on(cdp, session, node, context, PROBE) {
            Ok(probe) => probe,
            Err(VaultError::FieldNotFound(_)) => {
                return Err(VaultError::FieldNotFound(format!("no node {node} in this tab: read the page again")));
            }
            Err(other) => return Err(other),
        };
        if probe.mine {
            check_field(role, node, &probe, domain)?;
            return Ok(Located { node, role, frame_id: frame_id.clone(), context });
        }
    }
    Err(VaultError::FieldNotFound(format!("node {node} isn't in any frame of this tab")))
}

/// Resolves `node` in `context` and runs `function` on it, returning its value.
fn call_on<T: for<'de> Deserialize<'de>>(
    cdp: &mut DevTools,
    session: &str,
    node: u64,
    context: i64,
    function: &str,
) -> Result<T, VaultError> {
    let resolved = cdp
        .call("DOM.resolveNode", json!({ "backendNodeId": node, "executionContextId": context }), Some(session))
        .map_err(|error| match error {
            CdpError::Command(_) => VaultError::FieldNotFound(format!("no node {node}")),
            other => from_cdp(other),
        })?;
    let Some(object_id) = resolved["object"]["objectId"].as_str().map(str::to_string) else {
        return Err(VaultError::FieldNotFound(format!("no node {node}")));
    };
    let result = cdp.call(
        "Runtime.callFunctionOn",
        json!({ "objectId": object_id, "functionDeclaration": function, "returnByValue": true }),
        Some(session),
    );
    let _ = cdp.call("Runtime.releaseObject", json!({ "objectId": object_id }), Some(session));
    let result = result.map_err(from_cdp)?;
    if result.get("exceptionDetails").is_some() {
        return Err(VaultError::FieldNotFound(format!("node {node} couldn't be read")));
    }
    serde_json::from_value::<T>(result["result"]["value"].clone())
        .map_err(|_| VaultError::FieldNotFound(format!("node {node} couldn't be read")))
}

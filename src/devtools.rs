//! A small Chrome DevTools Protocol client for `fill`. It is the vault's one connection that
//! isn't a proxied request, and R25 allows it: a WebSocket to a DevTools port on 127.0.0.1, and
//! nowhere else.
//!
//! It is hand-written (an HTTP request, the WebSocket handshake, text frames) for the same
//! reason `SecretValue` exists. The one message that carries a password, `Input.insertText`, is
//! built in a buffer sized up front, so it never reallocates, and is masked in place. Every
//! buffer that held it, or any message read back, is wiped when dropped (R1). A WebSocket
//! library would copy the text into buffers of its own that nothing wipes.
//!
//! It never sends an `Origin` header. Chrome refuses DevTools WebSockets that carry one, unless
//! they come from `--remote-allow-origins`, so web pages can't use the port, and the vault needs
//! no such flag.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Serialize;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use crate::secret::WipingBuf;

/// The largest DevTools message the vault reads. Its replies are small: target info, a frame
/// tree, a probe's result.
const MAX_MESSAGE: usize = 8 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a DevTools call failed.
#[derive(Debug)]
pub enum CdpError {
    /// The connection: refused, closed, too slow, or not speaking DevTools.
    Transport(String),
    /// Chrome answered the command with an error (its message, for the vault's own log only).
    Command(String),
}

pub struct DevTools {
    stream: TcpStream,
    next_id: u64,
    deadline: Instant,
    /// What `/json/version` says the browser is (`Chrome/157.0.8103.78`), for the audit log.
    pub browser: String,
}

fn transport(why: impl Into<String>) -> CdpError {
    CdpError::Transport(why.into())
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

impl DevTools {
    /// Connects to the browser endpoint of the DevTools server on 127.0.0.1:`port`. The address
    /// is fixed here: nothing a caller sends can point it at another host.
    pub fn connect(port: u16, deadline: Instant) -> Result<DevTools, CdpError> {
        let (path, browser) = browser_endpoint(port, deadline)?;
        let mut stream = open(port, deadline)?;
        let mut key_bytes = [0u8; 16];
        getrandom::getrandom(&mut key_bytes).map_err(|_| transport("no random bytes for the handshake"))?;
        let key = BASE64.encode(key_bytes);
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).map_err(|_| transport("the handshake couldn't be sent"))?;
        let head = read_head(&mut stream)?;
        let head = String::from_utf8_lossy(&head).to_string();
        let status_ok = head.lines().next().is_some_and(|line| line.split(' ').nth(1) == Some("101"));
        if !status_ok {
            return Err(transport("the DevTools port refused the WebSocket"));
        }
        let mut accept = Sha1::new();
        accept.update(key.as_bytes());
        accept.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let expected = BASE64.encode(accept.finalize());
        let accepted = head.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("sec-websocket-accept") && value.trim() == expected
            })
        });
        if !accepted {
            return Err(transport("the DevTools port answered the handshake wrongly"));
        }
        Ok(DevTools { stream, next_id: 0, deadline, browser })
    }

    /// Sends one command and waits for its answer, skipping events. `session` is a flattened
    /// session id from `Target.attachToTarget`, or none for the browser itself.
    pub fn call(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<Value, CdpError> {
        self.next_id += 1;
        let id = self.next_id;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = Value::String(session.to_string());
        }
        let mut bytes = serde_json::to_vec(&message).map_err(|_| transport("encoding"))?;
        self.send_text(&mut bytes)?;
        self.answer(id)
    }

    /// `Input.insertText` with a value from the vault (R1): the one message that carries one.
    /// The message is written into a buffer big enough for any escaping, so it never grows and
    /// leaves no copy behind, then masked in place and sent. Chrome's answer is an empty result.
    pub fn insert_secret_text(&mut self, session: &str, text: &str) -> Result<(), CdpError> {
        #[derive(Serialize)]
        struct Params<'a> {
            text: &'a str,
        }
        #[derive(Serialize)]
        struct Message<'a> {
            id: u64,
            method: &'static str,
            params: Params<'a>,
            #[serde(rename = "sessionId")]
            session_id: &'a str,
        }
        self.next_id += 1;
        let id = self.next_id;
        // JSON escapes a character as at most six bytes (`\u001f`), and the rest is fixed text.
        let capacity = 128 + session.len() + text.len() * 6;
        let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
        serde_json::to_writer(&mut *buffer, &Message { id, method: "Input.insertText", params: Params { text }, session_id: session })
            .map_err(|_| transport("encoding"))?;
        if buffer.len() > capacity {
            // Can't happen (the bound above is exact); refuse rather than send from a buffer
            // that may have left a copy behind.
            return Err(transport("encoding"));
        }
        self.send_text(&mut buffer)?;
        self.answer(id).map(|_| ())
    }

    /// Reads messages until the answer to `id`, skipping events and other answers.
    fn answer(&mut self, id: u64) -> Result<Value, CdpError> {
        loop {
            let message = self.read_message()?;
            let Ok(value) = serde_json::from_slice::<Value>(message.as_slice()) else {
                return Err(transport("the DevTools port sent something that isn't JSON"));
            };
            if value.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = value.get("error") {
                let text = error.get("message").and_then(Value::as_str).unwrap_or("error");
                return Err(CdpError::Command(text.chars().take(200).collect()));
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// One text frame, masked as a client must. `payload` is masked in place: it is the caller's
    /// own buffer, wiped by the caller when it holds a value.
    fn send_text(&mut self, payload: &mut [u8]) -> Result<(), CdpError> {
        let mut mask = [0u8; 4];
        getrandom::getrandom(&mut mask).map_err(|_| transport("no random bytes for a frame mask"))?;
        let mut header = Vec::with_capacity(14);
        header.push(0x81); // FIN, text
        match payload.len() {
            len if len < 126 => header.push(0x80 | len as u8),
            len if len <= u16::MAX as usize => {
                header.push(0x80 | 126);
                header.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                header.push(0x80 | 127);
                header.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        header.extend_from_slice(&mask);
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        self.set_timeouts()?;
        self.stream.write_all(&header).map_err(|_| transport("the connection to the browser broke"))?;
        self.stream.write_all(payload).map_err(|_| transport("the connection to the browser broke"))?;
        Ok(())
    }

    fn send_control(&mut self, opcode: u8, payload: &[u8]) -> Result<(), CdpError> {
        let mut mask = [0u8; 4];
        getrandom::getrandom(&mut mask).map_err(|_| transport("no random bytes for a frame mask"))?;
        let mut frame = vec![0x80 | opcode, 0x80 | payload.len().min(125) as u8];
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().take(125).enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream.write_all(&frame).map_err(|_| transport("the connection to the browser broke"))
    }

    fn set_timeouts(&mut self) -> Result<(), CdpError> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(transport("the browser took too long"));
        }
        let _ = self.stream.set_read_timeout(Some(left));
        let _ = self.stream.set_write_timeout(Some(left));
        Ok(())
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), CdpError> {
        self.set_timeouts()?;
        self.stream.read_exact(buffer).map_err(|_| transport("the browser closed the connection or took too long"))
    }

    /// One whole message, its fragments joined, in a buffer that is wiped when dropped. Pings
    /// are answered; a close ends the call.
    fn read_message(&mut self) -> Result<WipingBuf, CdpError> {
        let mut message = WipingBuf::with_capacity(4096);
        loop {
            let mut head = [0u8; 2];
            self.read_exact(&mut head)?;
            let fin = head[0] & 0x80 != 0;
            let opcode = head[0] & 0x0f;
            let masked = head[1] & 0x80 != 0;
            let mut len = u64::from(head[1] & 0x7f);
            if len == 126 {
                let mut bytes = [0u8; 2];
                self.read_exact(&mut bytes)?;
                len = u64::from(u16::from_be_bytes(bytes));
            } else if len == 127 {
                let mut bytes = [0u8; 8];
                self.read_exact(&mut bytes)?;
                len = u64::from_be_bytes(bytes);
            }
            if len > MAX_MESSAGE as u64 || message.len() as u64 + len > MAX_MESSAGE as u64 {
                return Err(transport("the browser sent a message larger than the vault reads"));
            }
            let mut mask = [0u8; 4];
            if masked {
                self.read_exact(&mut mask)?;
            }
            let mut payload = Zeroizing::new(vec![0u8; len as usize]);
            self.read_exact(&mut payload)?;
            if masked {
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[index % 4];
                }
            }
            match opcode {
                0x0..=0x2 => {
                    message.extend_from_slice(&payload);
                    if fin {
                        return Ok(message);
                    }
                }
                0x8 => return Err(transport("the browser closed the connection")),
                0x9 => self.send_control(0xA, &payload)?,
                0xA => {}
                _ => return Err(transport("the browser sent a frame the vault doesn't know")),
            }
        }
    }
}

impl Drop for DevTools {
    fn drop(&mut self) {
        let _ = self.send_control(0x8, &1000u16.to_be_bytes());
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

fn open(port: u16, deadline: Instant) -> Result<TcpStream, CdpError> {
    let timeout = CONNECT_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
    if timeout.is_zero() {
        return Err(transport("the browser took too long"));
    }
    let stream = TcpStream::connect_timeout(&loopback(port), timeout)
        .map_err(|_| transport(format!("nothing answers on 127.0.0.1:{port}")))?;
    let _ = stream.set_nodelay(true);
    let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let _ = stream.set_read_timeout(Some(left));
    let _ = stream.set_write_timeout(Some(left));
    Ok(stream)
}

/// Reads an HTTP response head, a byte at a time so nothing past it is consumed.
fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>, CdpError> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(transport("the DevTools port sent an overlong answer"));
        }
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return Err(transport("the DevTools port didn't answer")),
        }
    }
    Ok(head)
}

/// `GET /json/version`: the browser endpoint's path (`/devtools/browser/<id>`) and the
/// browser's name and version. Only the path is taken from the answer, never a host or port.
fn browser_endpoint(port: u16, deadline: Instant) -> Result<(String, String), CdpError> {
    let mut stream = open(port, deadline)?;
    let request = format!("GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|_| transport("the DevTools port didn't take a request"))?;
    let head = read_head(&mut stream)?;
    let head = String::from_utf8_lossy(&head).to_string();
    if head.lines().next().and_then(|line| line.split(' ').nth(1)) != Some("200") {
        return Err(transport(format!("127.0.0.1:{port} isn't a DevTools port")));
    }
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok()).flatten()
    });
    let mut body = Vec::new();
    match length {
        Some(len) if len <= 64 * 1024 => {
            body.resize(len, 0);
            stream.read_exact(&mut body).map_err(|_| transport("the DevTools port's answer was cut short"))?;
        }
        Some(_) => return Err(transport("the DevTools port sent an overlong answer")),
        None => {
            stream.take(64 * 1024).read_to_end(&mut body).map_err(|_| transport("the DevTools port's answer was cut short"))?;
        }
    }
    let version: Value =
        serde_json::from_slice(&body).map_err(|_| transport(format!("127.0.0.1:{port} isn't a DevTools port")))?;
    let url = version.get("webSocketDebuggerUrl").and_then(Value::as_str).unwrap_or("");
    let path = url.find("/devtools/browser/").map(|at| &url[at..]).unwrap_or("");
    let id = path.trim_start_matches("/devtools/browser/");
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(transport(format!("127.0.0.1:{port} has no browser endpoint")));
    }
    let browser: String = version
        .get("Browser")
        .and_then(Value::as_str)
        .unwrap_or("unknown browser")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    Ok((path.to_string(), browser))
}

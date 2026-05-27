//! DNS server implementations for all transport types.
//!
//! Sprint 1-1: UDP, TCP, DoT (DNS over TLS), DoH (DNS over HTTPS), DoJ (JSON facade).
//! DoQ (DNS over QUIC) is deferred to a later sprint.
//!
//! Fixes applied:
//! - IPv6 dual-stack: set `IPV6_V6ONLY=0` on all TCP/UDP sockets so that
//!   binding `[::]` also accepts IPv4 connections (Windows default is v6-only).
//! - Rebind retry: every server loop retries bind with exponential backoff
//!   on socket-level failure, instead of silently exiting.
//! - UDP receive buffer set to 256 KB for high-throughput scenarios.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::Query;
use axum::extract::State;
use axum::http::Method;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use border_dns_config::DoHListenerConfig;
use border_dns_config::DoJListenerConfig;
use border_dns_config::TlsListenerConfig;
use dns_protocol::header::ResponseCode;
use dns_protocol::message::DnsMessage;
use dns_protocol::tcp_frame;
use dns_transport::RequestMeta;
use dns_transport::TransportKind;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::RuntimeContext;
use crate::handler;

// ─── Rebind helper ───────────────────────────────────────────────

/// Maximum backoff when re-binding a socket after failure.
const MAX_REBIND_BACKOFF: Duration = Duration::from_secs(60);

/// Minimum backoff when re-binding.
const MIN_REBIND_BACKOFF: Duration = Duration::from_secs(1);

/// Rebind loop: calls `bind_fn` in a retry loop with exponential backoff.
/// Yields each successfully bound value to `on_ready` which runs the server
/// loop. If the server loop returns (error or success), the bind is retried.
async fn rebind_loop<F, Fut, B, R, RFut>(
    name: &str,
    addr: &str,
    mut bind_fn: F,
    mut on_ready: R,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<B>>,
    R: FnMut(B) -> RFut,
    RFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut backoff = MIN_REBIND_BACKOFF;

    loop {
        match bind_fn().await {
            Ok(bound) => {
                backoff = MIN_REBIND_BACKOFF;
                info!(address = %addr, "{name} server listening");
                match on_ready(bound).await {
                    Ok(()) => {
                        warn!(address = %addr, "{name} server exited cleanly, rebinding");
                    }
                    Err(e) => {
                        error!(address = %addr, error = %e, "{name} server error, rebinding");
                    }
                }
            }
            Err(e) => {
                error!(
                    address = %addr,
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "{name} bind failed, retrying"
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_REBIND_BACKOFF);
    }
}

// ─── Dual-stack socket helper ────────────────────────────────────

/// Create a `socket2::Socket` bound to `addr` with dual-stack enabled.
///
/// On IPv6 addresses, sets `IPV6_V6ONLY=0` so that `[::]` accepts both
/// IPv4 and IPv6 connections (fixes Windows default of v6-only).
fn bind_dual_stack_udp(addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::Protocol;
    use socket2::SockAddr;
    use socket2::Type;

    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(false)?;
    }
    sock.set_reuse_address(true)?;
    sock.bind(&SockAddr::from(addr))?;
    sock.set_nonblocking(true)?;
    // Bump receive buffer for high-throughput DNS.
    let _ = sock.set_recv_buffer_size(256 * 1024);
    let _ = sock.set_send_buffer_size(256 * 1024);
    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock)
}

/// Create a `socket2::Socket` for TCP listening with dual-stack enabled.
fn bind_dual_stack_tcp(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::Protocol;
    use socket2::SockAddr;
    use socket2::Type;

    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(false)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_tcp_nodelay(true)?;
    sock.bind(&SockAddr::from(addr))?;
    // DNS servers don't need large backlog — 128 is plenty.
    sock.listen(128)?;
    sock.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = sock.into();
    tokio::net::TcpListener::from_std(std_listener)
}

// ─── UDP DNS Server ───────────────────────────────────────────────

/// Run a UDP DNS server on the given address.
///
/// Uses `socket2` for dual-stack IPv6 (IPV6_V6ONLY=0). If the socket
/// errors out (e.g. after Windows hibernation), automatically rebinds
/// with exponential backoff.
pub async fn run_udp(addr: String, ctx: Arc<RuntimeContext>) -> anyhow::Result<()> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid UDP listen address '{addr}': {e}"))?;

    rebind_loop(
        "UDP",
        &addr,
        || {
            let addr = sock_addr;
            async move {
                bind_dual_stack_udp(addr).map_err(|e| anyhow::anyhow!("UDP bind '{addr}': {e}"))
            }
        },
        |socket| {
            let ctx = Arc::clone(&ctx);
            async move {
                let socket = Arc::new(socket);
                loop {
                    let mut buf = vec![0u8; 4096];
                    let sock = Arc::clone(&socket);
                    let ctx = Arc::clone(&ctx);

                    let (len, peer) = match sock.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(e) => {
                            // Fatal socket error → return Err to trigger rebind.
                            error!(error = %e, "UDP recv fatal error, rebinding");
                            return Err(e.into());
                        }
                    };
                    buf.truncate(len);

                    ctx.metrics.udp.record_request();

                    tokio::spawn(async move {
                        let meta = RequestMeta::new(TransportKind::Udp, Some(peer));
                        let resp = handler::handle_dns_query(&buf, &ctx, &meta).await;
                        if let Err(e) = sock.send_to(resp.wire(), peer).await {
                            debug!(error = %e, peer = %peer, "UDP send error");
                        }
                    });
                }
            }
        },
    )
    .await
}

// ─── TCP DNS Server ───────────────────────────────────────────────

/// Run a TCP DNS server on the given address.
///
/// Uses dual-stack socket with rebind retry.
pub async fn run_tcp(addr: String, ctx: Arc<RuntimeContext>) -> anyhow::Result<()> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid TCP listen address '{addr}': {e}"))?;

    rebind_loop(
        "TCP",
        &addr,
        || {
            let addr = sock_addr;
            async move {
                bind_dual_stack_tcp(addr).map_err(|e| anyhow::anyhow!("TCP bind '{addr}': {e}"))
            }
        },
        |listener| {
            let ctx = Arc::clone(&ctx);
            async move {
                let timeout_dur = Duration::from_millis(ctx.config.server.default_timeout_ms);
                loop {
                    let (stream, peer) = listener.accept().await?;
                    let ctx = Arc::clone(&ctx);

                    tokio::spawn(async move {
                        ctx.metrics.tcp.record_request();
                        if let Err(e) = handle_tcp_connection(stream, peer, ctx, timeout_dur).await
                        {
                            debug!(error = %e, peer = %peer, "TCP connection error");
                        }
                    });
                }
            }
        },
    )
    .await
}

/// Handle a single TCP DNS connection (may contain multiple queries).
async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    ctx: Arc<RuntimeContext>,
    timeout_dur: Duration,
) -> anyhow::Result<()> {
    let mut decoder = tcp_frame::TcpFrameDecoder::new();

    loop {
        let mut buf = vec![0u8; 4096];
        let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!(peer = %peer, "TCP read timeout");
                return Ok(());
            }
        };

        decoder.feed(&buf[..n]);

        loop {
            match decoder.try_decode() {
                Ok(Some((msg_bytes, _))) => {
                    let meta = RequestMeta::new(TransportKind::Tcp, Some(peer));
                    let resp = handler::handle_dns_query(&msg_bytes, &ctx, &meta).await;
                    let frame = tcp_frame::encode_tcp_frame(resp.wire());
                    if let Err(e) = timeout(timeout_dur, stream.write_all(&frame)).await {
                        debug!(error = %e, peer = %peer, "TCP write error");
                        return Ok(());
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, peer = %peer, "TCP frame decode error");
                    decoder.reset();
                    break;
                }
            }
        }
    }
}

// ─── DoT DNS Server (RFC 7858) ───────────────────────────────────

/// Run a DNS-over-TLS server.
///
/// DoT = TLS stream + DNS-over-TCP framing (2-byte length prefix).
/// Uses dual-stack TCP socket with rebind retry.
pub async fn run_dot(cfg: TlsListenerConfig, ctx: Arc<RuntimeContext>) -> anyhow::Result<()> {
    let tls_config = load_tls_server_config(&cfg.cert_file, &cfg.key_file)?;
    let tls_config = Arc::new(tls_config);
    let sock_addr: SocketAddr = cfg
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DoT listen address '{}': {}", cfg.listen, e))?;

    rebind_loop(
        "DoT",
        &cfg.listen,
        || {
            let addr = sock_addr;
            async move {
                bind_dual_stack_tcp(addr).map_err(|e| anyhow::anyhow!("DoT bind '{addr}': {e}"))
            }
        },
        |listener| {
            let ctx = Arc::clone(&ctx);
            let tls_config = Arc::clone(&tls_config);
            let idle_timeout = Duration::from_millis(cfg.idle_timeout_ms);
            async move {
                loop {
                    let (stream, peer) = listener.accept().await?;
                    let ctx = Arc::clone(&ctx);
                    let tls_config = Arc::clone(&tls_config);

                    tokio::spawn(async move {
                        ctx.metrics.tls.record_request();
                        if let Err(e) =
                            handle_tls_connection(stream, peer, ctx, tls_config, idle_timeout).await
                        {
                            debug!(error = %e, peer = %peer, "DoT connection error");
                        }
                    });
                }
            }
        },
    )
    .await
}

/// Handle a TLS DNS connection (DoT).
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    ctx: Arc<RuntimeContext>,
    tls_config: Arc<rustls::ServerConfig>,
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let mut tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {e}"))?;

    let mut decoder = tcp_frame::TcpFrameDecoder::new();

    loop {
        let mut buf = vec![0u8; 4096];
        let n = match timeout(idle_timeout, tls_stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!(peer = %peer, "DoT idle timeout");
                return Ok(());
            }
        };

        decoder.feed(&buf[..n]);

        loop {
            match decoder.try_decode() {
                Ok(Some((msg_bytes, _))) => {
                    let meta = RequestMeta::new(TransportKind::Tls, Some(peer));
                    let resp = handler::handle_dns_query(&msg_bytes, &ctx, &meta).await;
                    let frame = tcp_frame::encode_tcp_frame(resp.wire());
                    if let Err(e) = timeout(idle_timeout, tls_stream.write_all(&frame)).await {
                        debug!(error = %e, peer = %peer, "DoT write error");
                        return Ok(());
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, peer = %peer, "DoT frame decode error");
                    decoder.reset();
                    break;
                }
            }
        }
    }
}

// ─── DoH DNS Server (RFC 8484) ───────────────────────────────────

/// Run a DNS-over-HTTPS server using `axum_server` with TLS.
///
/// Supports:
/// - GET `/dns-query?dns=<base64url>` (RFC 8484 Section 2.1)
/// - POST `/dns-query` with `application/dns-message`
///
/// Uses `axum_server::bind_rustls` for TLS termination — no manual
/// hyper connection handling needed.
///
/// Note: `axum_server` manages its own socket, so dual-stack is not
/// directly controllable. If IPv6-only is needed, bind to `[::]` and
/// add a second listener for `0.0.0.0`.
///
/// # Errors
///
/// Returns error on TLS config or bind failure.
pub async fn run_doh(cfg: DoHListenerConfig, ctx: Arc<RuntimeContext>) -> anyhow::Result<()> {
    let path = cfg.path.clone();

    let app = Router::new()
        .route(
            &path,
            get(doh_get_handler)
                .post(doh_post_handler)
                .options(doh_options_handler),
        )
        .with_state(Arc::clone(&ctx))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([CONTENT_TYPE, axum::http::header::ACCEPT]),
        );

    let addr: std::net::SocketAddr = cfg
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DoH listen address '{}': {}", cfg.listen, e))?;

    let tls_config =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(&cfg.cert_file, &cfg.key_file)
            .await
            .map_err(|e| anyhow::anyhow!("failed to load TLS config: {e}"))?;

    info!(address = %cfg.listen, path = %cfg.path, "DoH server listening");

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("DoH server error: {e}"))
}

/// DoH GET handler: `GET /dns-query?dns=<base64url>`
async fn doh_get_handler(
    State(ctx): State<Arc<RuntimeContext>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Bytes, (StatusCode, String)> {
    let dns_b64 = params.get("dns").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing 'dns' query parameter".into(),
        )
    })?;

    let query_bytes = dns_protocol::transport::doh_decode_get(dns_b64).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid dns parameter: {e}"),
        )
    })?;

    ctx.metrics.https.record_request();
    let meta = RequestMeta::new(TransportKind::Https, None);
    let resp = handler::handle_dns_query(&query_bytes, &ctx, &meta).await;
    Ok(Bytes::from(resp.into_wire()))
}

/// DoH POST handler: `POST /dns-query` with `application/dns-message`
async fn doh_post_handler(
    State(ctx): State<Arc<RuntimeContext>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Bytes, (StatusCode, String)> {
    // Validate Content-Type.
    if let Some(ct) = headers.get(CONTENT_TYPE) {
        let ct_str = ct.to_str().unwrap_or("");
        if !ct_str.contains("application/dns-message") {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("expected application/dns-message, got {ct_str}"),
            ));
        }
    }

    let query_bytes = dns_protocol::transport::doh_decode_post(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid DoH body: {e}")))?;

    ctx.metrics.https.record_request();
    let meta = RequestMeta::new(TransportKind::Https, None);
    let resp = handler::handle_dns_query(&query_bytes, &ctx, &meta).await;
    Ok(Bytes::from(resp.into_wire()))
}

/// DoH OPTIONS handler (preflight).
async fn doh_options_handler() -> StatusCode {
    StatusCode::NO_CONTENT
}

// ─── DoJ DNS-over-JSON Facade ─────────────────────────────────────

/// JSON DNS response (Google Public DNS compatible format).
#[derive(Debug, serde::Serialize)]
struct DoJResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "TC")]
    tc: bool,
    #[serde(rename = "RD")]
    rd: bool,
    #[serde(rename = "RA")]
    ra: bool,
    #[serde(rename = "AD", skip_serializing_if = "Option::is_none")]
    ad: Option<bool>,
    #[serde(rename = "CD", skip_serializing_if = "Option::is_none")]
    cd: Option<bool>,
    #[serde(rename = "Question")]
    question: Vec<DoJQuestionEntry>,
    #[serde(rename = "Answer", skip_serializing_if = "Vec::is_empty")]
    answer: Vec<DoJAnswer>,
}

#[derive(Debug, serde::Serialize)]
struct DoJQuestionEntry {
    name: String,
    #[serde(rename = "type")]
    r#type: u16,
}

/// A JSON DNS answer record.
#[derive(Debug, serde::Serialize)]
struct DoJAnswer {
    name: String,
    #[serde(rename = "type")]
    r#type: u16,
    ttl: u32,
    data: String,
}

/// Run a DNS-over-JSON facade server.
///
/// Provides a Google Public DNS compatible JSON API:
/// ```text
/// GET /resolve?name=example.com&type=A
/// ```
///
/// Uses dual-stack TCP socket with rebind retry.
///
/// # Errors
///
/// Returns error on bind failure.
pub async fn run_doj(cfg: DoJListenerConfig, ctx: Arc<RuntimeContext>) -> anyhow::Result<()> {
    let path = cfg.path.clone();
    let sock_addr: SocketAddr = cfg
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DoJ listen address '{}': {}", cfg.listen, e))?;

    rebind_loop(
        "DoJ",
        &cfg.listen,
        || {
            let addr = sock_addr;
            async move {
                bind_dual_stack_tcp(addr).map_err(|e| anyhow::anyhow!("DoJ bind '{addr}': {e}"))
            }
        },
        |listener| {
            let ctx = Arc::clone(&ctx);
            let path = path.clone();
            let profile = cfg.profile.clone();
            async move {
                let app = Router::new()
                    .route(&path, get(doj_resolve_handler))
                    .with_state(Arc::clone(&ctx));

                info!(
                    path = %path,
                    profile = %profile,
                    "DoJ handler registered"
                );

                axum::serve(listener, app.into_make_service())
                    .await
                    .map_err(|e| anyhow::anyhow!("DoJ server error: {e}"))
            }
        },
    )
    .await
}

/// DoJ resolve handler: `GET /resolve?name=example.com&type=A`
async fn doj_resolve_handler(
    State(ctx): State<Arc<RuntimeContext>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    ctx.metrics.json.record_request();
    let name = match params.get("name") {
        Some(n) => n.clone(),
        None => {
            let resp = DoJResponse {
                status: 1, // SERVFAIL
                tc: false,
                rd: false,
                ra: false,
                ad: None,
                cd: None,
                question: vec![],
                answer: vec![],
            };
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::to_value(&resp).unwrap()),
            )
                .into_response();
        }
    };

    // Parse type parameter.
    let qtype_str = params.get("type").map(String::as_str).unwrap_or("A");
    let qtype_val = if let Ok(n) = qtype_str.parse::<u16>() {
        n
    } else {
        match qtype_str.to_uppercase().as_str() {
            "A" => 1,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            "SRV" => 33,
            "HTTPS" => 65,
            "SVCB" => 64,
            _ => 1,
        }
    };

    // Build DNS wire query.
    let dns_name = ensure_trailing_dot(&name);
    let wire_query = match build_wire_query(&dns_name, qtype_val) {
        Ok(w) => w,
        Err(_) => {
            let resp = DoJResponse {
                status: 1,
                tc: false,
                rd: false,
                ra: false,
                ad: None,
                cd: None,
                question: vec![],
                answer: vec![],
            };
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::to_value(&resp).unwrap()),
            )
                .into_response();
        }
    };

    // Resolve through unified pipeline.
    let meta = RequestMeta::new(TransportKind::Json, None);
    let handler_resp = handler::handle_dns_query(&wire_query, &ctx, &meta).await;

    // Convert to JSON response.
    let doj_resp = wire_to_json_response(&dns_name, qtype_val, handler_resp.message());

    (
        StatusCode::OK,
        axum::Json(serde_json::to_value(&doj_resp).unwrap()),
    )
        .into_response()
}

/// Ensure a domain name has a trailing dot.
fn ensure_trailing_dot(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// Build a minimal DNS wire-format query.
fn build_wire_query(name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    use dns_protocol::name::DomainName;
    use dns_protocol::question::DnsQuestion;
    use dns_types::QClass;
    use dns_types::QType;
    use dns_types::RecordType;

    let domain = DomainName::from_str(name).map_err(|e| format!("invalid domain: {e}"))?;
    let rt = RecordType::from_u16(qtype);
    let qt = QType::Type(rt);
    let qc = QClass::Class(dns_types::RecordClass::In);

    let q = DnsQuestion::new(domain, qt, qc);
    let mut msg = DnsMessage::query(rand_id(), q);
    msg.header.rd = true;

    Ok(msg.to_wire())
}

/// Generate a random DNS message ID.
fn rand_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;
    use std::hash::Hasher;
    let s = RandomState::new();
    let mut hasher = s.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    hasher.finish() as u16
}

/// Convert a DNS wire response to a DoJ JSON response.
fn wire_to_json_response(name: &str, qtype: u16, resp: &DnsMessage) -> DoJResponse {
    let status = match resp.header.rcode {
        ResponseCode::NoError => 0,
        ResponseCode::FormErr => 1,
        ResponseCode::ServFail => 2,
        ResponseCode::NXDomain => 3,
        ResponseCode::NotImp => 4,
        ResponseCode::Refused => 5,
        _ => 2,
    };

    let question = vec![DoJQuestionEntry {
        name: name.to_string(),
        r#type: qtype,
    }];

    let mut answer = Vec::new();
    for rr in &resp.answers {
        let data = format_rr_data(rr);
        answer.push(DoJAnswer {
            name: rr.name.to_string(),
            r#type: rr.rr_type.as_u16(),
            ttl: rr.ttl,
            data,
        });
    }

    DoJResponse {
        status,
        tc: resp.header.tc,
        rd: resp.header.rd,
        ra: resp.header.ra,
        ad: None,
        cd: None,
        question,
        answer,
    }
}

/// Format an RData value as a string for JSON response.
fn format_rr_data(rr: &dns_protocol::rr::ResourceRecord) -> String {
    use dns_protocol::rr::RData;
    match &rr.rdata {
        RData::A(ip) => ip.to_string(),
        RData::AAAA(ip) => ip.to_string(),
        RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => name.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
        RData::TXT(txts) => {
            let parts: Vec<String> = txts
                .iter()
                .map(|s| {
                    let quoted = String::from_utf8_lossy(s);
                    format!("\"{quoted}\"")
                })
                .collect();
            parts.join(" ")
        }
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
        ),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        RData::SVCB(svcb) | RData::HTTPS(svcb) => {
            format!("{} {}", svcb.priority, svcb.target)
        }
        RData::OPT(_) => String::new(),
        RData::Unknown { .. } => String::new(),
    }
}

// ─── TLS Helpers ──────────────────────────────────────────────────

/// Load a rustls `ServerConfig` from PEM certificate and key files.
fn load_tls_server_config(cert_file: &str, key_file: &str) -> anyhow::Result<rustls::ServerConfig> {
    let cert_data = std::fs::read(cert_file)
        .map_err(|e| anyhow::anyhow!("failed to read TLS cert '{cert_file}': {e}"))?;
    let key_data = std::fs::read(key_file)
        .map_err(|e| anyhow::anyhow!("failed to read TLS key '{key_file}': {e}"))?;

    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_data))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("failed to parse TLS certs: {e}"))?;

    if cert_chain.is_empty() {
        anyhow::bail!("no TLS certificates found in '{cert_file}'");
    }

    let key_der = rustls_pemfile::private_key(&mut std::io::Cursor::new(&key_data))
        .map_err(|e| anyhow::anyhow!("failed to parse TLS key: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in '{key_file}'"))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;

    // Set ALPN for DoT.
    config.alpn_protocols = vec![b"dns".to_vec()];

    Ok(config)
}

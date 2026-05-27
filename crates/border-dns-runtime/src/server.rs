//! UDP and TCP DNS server implementations.

use std::sync::Arc;
use std::time::Duration;

use dns_protocol::message::DnsMessage;
use dns_protocol::tcp_frame;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::RuntimeContext;

/// Run a UDP DNS server on the given address.
///
/// Handles each incoming query independently. Forwards to upstream and caches the response.
///
/// # Errors
///
/// Returns error on socket bind failure.
pub async fn run_udp(addr: String, ctx: Arc<RuntimeContext>) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    info!(address = %addr, "UDP server listening");

    let timeout_dur = Duration::from_secs(ctx.config.server.request_timeout_secs);

    loop {
        let mut buf = vec![0u8; 4096];
        let socket = Arc::clone(&socket);
        let ctx = Arc::clone(&ctx);

        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "UDP recv error");
                continue;
            }
        };
        buf.truncate(len);

        tokio::spawn(async move {
            if let Err(e) = handle_udp_query(buf, peer, socket, ctx, timeout_dur).await {
                debug!(error = %e, peer = %peer, "UDP query handling error");
            }
        });
    }
}

/// Handle a single UDP DNS query.
async fn handle_udp_query(
    query_bytes: Vec<u8>,
    peer: std::net::SocketAddr,
    socket: Arc<UdpSocket>,
    ctx: Arc<RuntimeContext>,
    timeout_dur: Duration,
) -> anyhow::Result<()> {
    let query =
        DnsMessage::from_wire(&query_bytes).map_err(|e| anyhow::anyhow!("malformed query: {e}"))?;

    let (qtype, domain) = match query.first_question() {
        Some(q) => (q.qtype, q.qname.clone()),
        None => {
            // Respond with FormErr for queries with no question.
            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = dns_protocol::header::ResponseCode::FormErr;
            let resp_bytes = resp.to_wire();
            socket.send_to(&resp_bytes, peer).await?;
            return Ok(());
        }
    };

    // Check cache first.
    if let Some(cached) = ctx.cache.get(qtype, &domain) {
        let mut resp = cached;
        resp.header.id = query.header.id;
        let resp_bytes = resp.to_wire();
        socket.send_to(&resp_bytes, peer).await?;
        return Ok(());
    }

    // Forward to upstream with timeout.
    let resp = match timeout(
        timeout_dur,
        border_dns_upstream::forward(&query, &ctx.config.upstreams.default, timeout_dur),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            warn!(error = %e, domain = %domain, "upstream failed");
            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = dns_protocol::header::ResponseCode::ServFail;
            let resp_bytes = resp.to_wire();
            socket.send_to(&resp_bytes, peer).await?;
            return Ok(());
        }
        Err(_) => {
            warn!(domain = %domain, "upstream timeout");
            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = dns_protocol::header::ResponseCode::ServFail;
            let resp_bytes = resp.to_wire();
            socket.send_to(&resp_bytes, peer).await?;
            return Ok(());
        }
    };

    // Cache the response.
    if resp.message.header.rcode == dns_protocol::header::ResponseCode::NoError
        && !resp.message.answers.is_empty()
    {
        ctx.cache.insert(qtype, &domain, resp.message.clone());
    }

    // Send response.
    let resp_bytes = resp.message.to_wire();
    socket.send_to(&resp_bytes, peer).await?;
    Ok(())
}

/// Run a TCP DNS server on the given address.
///
/// Accepts connections and handles each in a separate task.
///
/// # Errors
///
/// Returns error on bind failure.
pub async fn run_tcp(addr: String, ctx: Arc<RuntimeContext>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(address = %addr, "TCP server listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = Arc::clone(&ctx);

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, peer, ctx).await {
                debug!(error = %e, peer = %peer, "TCP connection error");
            }
        });
    }
}

/// Handle a single TCP DNS connection (may contain multiple queries).
async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    ctx: Arc<RuntimeContext>,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let timeout_dur = Duration::from_secs(ctx.config.server.request_timeout_secs);
    let mut decoder = tcp_frame::TcpFrameDecoder::new();

    loop {
        // Read bytes from TCP stream.
        let mut buf = vec![0u8; 4096];
        let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()), // Connection closed.
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!(peer = %peer, "TCP read timeout");
                return Ok(());
            }
        };

        decoder.feed(&buf[..n]);

        // Process all complete frames in the buffer.
        loop {
            match decoder.try_decode() {
                Ok(Some((msg_bytes, _))) => {
                    let resp = handle_tcp_query(msg_bytes, &ctx).await;

                    // Send response with TCP length prefix.
                    let frame = tcp_frame::encode_tcp_frame(&resp);
                    if let Err(e) = timeout(timeout_dur, stream.write_all(&frame)).await {
                        debug!(error = %e, peer = %peer, "TCP write error");
                        return Ok(());
                    }
                }
                Ok(None) => break, // Need more data.
                Err(e) => {
                    warn!(error = %e, peer = %peer, "TCP frame decode error");
                    decoder.reset();
                    break;
                }
            }
        }
    }
}

/// Handle a single DNS query over TCP (same logic as UDP but without socket send).
async fn handle_tcp_query(query_bytes: Vec<u8>, ctx: &Arc<RuntimeContext>) -> Vec<u8> {
    let query = match DnsMessage::from_wire(&query_bytes) {
        Ok(q) => q,
        Err(_) => {
            // Can't even parse the query — return empty response.
            return Vec::new();
        }
    };

    let (qtype, domain) = match query.first_question() {
        Some(q) => (q.qtype, q.qname.clone()),
        None => {
            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = dns_protocol::header::ResponseCode::FormErr;
            return resp.to_wire();
        }
    };

    // Check cache.
    if let Some(cached) = ctx.cache.get(qtype, &domain) {
        let mut resp = cached;
        resp.header.id = query.header.id;
        return resp.to_wire();
    }

    // Forward to upstream.
    let timeout_dur = Duration::from_secs(ctx.config.server.request_timeout_secs);
    match border_dns_upstream::forward(&query, &ctx.config.upstreams.default, timeout_dur).await {
        Ok(resp) => {
            if resp.message.header.rcode == dns_protocol::header::ResponseCode::NoError
                && !resp.message.answers.is_empty()
            {
                ctx.cache.insert(qtype, &domain, resp.message.clone());
            }
            resp.message.to_wire()
        }
        Err(e) => {
            warn!(error = %e, domain = %domain, "TCP upstream failed");
            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = dns_protocol::header::ResponseCode::ServFail;
            resp.to_wire()
        }
    }
}

//! Name resolution for the supervisor's own outbound sockets.
//!
//! Every address the supervisor dials starts as a name: a Lens Sandbox
//! upstream, a TLS-bridge target, or the host a workload asked for over a
//! `transport: direct` route. Resolving it is the supervisor's own traffic, so
//! it belongs on the marked path with every other socket the supervisor opens
//! (see [`crate::sock_mark`]).
//!
//! `getaddrinfo` cannot go on that path. libc opens the query socket, and only
//! a socket we open ourselves can carry `SO_MARK`, so a libc lookup is an
//! unmarked UDP/53 query — which the cage redirects into the DNS stub. The stub
//! judges the *querying process* against a route's `binaries` filter, and the
//! supervisor is not the workload the filter names. Resolving here instead
//! keeps the stub judging workload lookups only, which is the one caller a
//! `binaries` rule can speak about. The policy still decides every dial: a door
//! admits the name before the supervisor resolves it, and the connect guard
//! re-reads the tables against the resolved address.
//!
//! `/etc/hosts` and the resolv.conf `search` list are honoured, because a
//! container's own names (`host.docker.internal`, a bare Kubernetes service)
//! live in one or the other.
//!
//! The `nameserver` lines are read as an ordered list and asked one at a time,
//! the way libc reads them. A split-DNS deployment writes the internal resolver
//! first and a public one after it as a fallback. Querying both at once would
//! put them in a race the fast one wins, and a public `NXDOMAIN` arriving ahead
//! of the internal answer would deny a name that does resolve.
//!
//! Only A records are asked for — every dial, a workload's target and the
//! supervisor's own infrastructure alike. The sandbox egresses over IPv4: the
//! transparent interceptor reads no other family, and the stub answers NODATA
//! to AAAA, so inside the cage a AAAA answer has never arrived. Asking for one
//! here would open a path for the supervisor that nothing else in the sandbox
//! has, past `egress.tcp` CIDR rules an operator wrote in IPv4. A host that
//! publishes only AAAA is therefore unreachable, and that is the same answer
//! the stub already gives.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{LookupIpStrategy, ResolveHosts, ServerOrderingStrategy};
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{
    RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime,
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// How long to wait for a TCP connection to the upstream resolver. Only a
/// truncated UDP answer falls back to TCP, so this bounds a rare retry rather
/// than the ordinary lookup.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The Tokio runtime the resolver runs on, with `SO_MARK` on every socket it
/// opens. The mark is the whole point of the module: it is what takes a query
/// to the upstream resolver instead of into the sandbox's own DNS stub.
#[derive(Clone, Default)]
struct MarkedRuntime(TokioRuntimeProvider);

impl RuntimeProvider for MarkedRuntime {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        Box::pin(async move {
            // Built here rather than handed to the inner provider, because the
            // mark has to be on the socket before the SYN leaves.
            let socket = if server.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            crate::sock_mark::mark(&socket)?;
            if let Some(bind) = bind {
                socket.bind(bind)?;
            }
            socket.set_nodelay(true)?;
            let wait_for = wait_for.unwrap_or(TCP_CONNECT_TIMEOUT);
            match tokio::time::timeout(wait_for, socket.connect(server)).await {
                Ok(connected) => connected.map(AsyncIoTokioAsStd),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("resolver TCP connect to {server} timed out"),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        _server: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        Box::pin(crate::sock_mark::bind_udp(local))
    }
}

/// The first address `host` resolves to, as a `SocketAddr` on `port`.
///
/// An address literal is returned as it stands: it needs no nameserver, and
/// every egress guard is written against the address anyway. Both spellings of
/// an IPv6 literal count as one, because `http::Uri::host` keeps the brackets
/// and a DNS name can never carry them. A name goes to the resolver, and the
/// first A record wins — reconnect loops at the call site cover a single
/// address that is down.
///
/// UNCHECKED: the answer may be loopback, link-local, or unspecified. Callers
/// dialing sandbox egress must use [`crate::sock_mark::connect_tcp_egress`],
/// which applies the floor.
pub async fn resolve_first(host: &str, port: u16) -> io::Result<SocketAddr> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let answer = resolver()?
        .lookup_ip(host)
        .await
        .map_err(|e| io::Error::other(format!("resolve {host}: {e}")))?;
    answer
        .iter()
        .next()
        .map(|ip| SocketAddr::new(ip, port))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no addrs for {host}")))
}

/// The process-wide resolver, built on first use. One instance shares one
/// cache and reads the system configuration once; a per-dial resolver would
/// re-parse `/etc/resolv.conf` and throw the cache away.
///
/// Only a working resolver is kept. A first dial can arrive before the file it
/// reads is finished — Docker and kubelet both write `resolv.conf` after the
/// root filesystem exists — and a remembered failure would then outlive the
/// thing that caused it and refuse every name for as long as the sandbox runs.
/// The next dial reads the file again instead, which costs one read beside a
/// lookup that was going to wait for the network anyway.
fn resolver() -> io::Result<&'static Resolver<MarkedRuntime>> {
    static RESOLVER: OnceLock<Resolver<MarkedRuntime>> = OnceLock::new();
    if let Some(resolver) = RESOLVER.get() {
        return Ok(resolver);
    }
    let built = build_resolver().map_err(io::Error::other)?;
    Ok(RESOLVER.get_or_init(|| built))
}

fn build_resolver() -> Result<Resolver<MarkedRuntime>, String> {
    let mut builder = Resolver::builder(MarkedRuntime::default())
        .map_err(|e| format!("read resolver configuration: {e}"))?;
    let options = builder.options_mut();
    options.ip_strategy = LookupIpStrategy::Ipv4Only;
    options.use_hosts_file = ResolveHosts::Always;
    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    builder.build().map_err(|e| format!("build resolver: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_address_literal_needs_no_nameserver() {
        // Every spelling a door hands over: a plain literal, the mapped IPv6
        // form, and the bracketed one a `Uri` authority carries.
        assert_eq!(
            resolve_first("10.0.0.5", 22).await.unwrap(),
            "10.0.0.5:22".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_first("::ffff:127.0.0.1", 9).await.unwrap(),
            "[::ffff:127.0.0.1]:9".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_first("[::1]", 9).await.unwrap(),
            "[::1]:9".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn a_hosts_file_name_resolves_without_a_query() {
        // `getaddrinfo` read /etc/hosts, so this resolver has to as well —
        // `localhost` and a container's own names are only there.
        let addr = resolve_first("localhost", 9).await.unwrap();
        assert!(addr.ip().is_loopback(), "expected loopback, got {addr}");
        assert_eq!(addr.port(), 9);
    }
}

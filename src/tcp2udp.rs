//! Primitives for listening on TCP and forwarding the data in incoming connections
//! to UDP.
// TODO: Consider adding a feature flag for TLS to conditionally compile tokio_rustls related code.

use crate::exponential_backoff::ExponentialBackoff;
use crate::logging::Redact;
use err_context::{BoxedErrorExt as _, ErrorExt as _, ResultExt as _};
use std::convert::Infallible;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
// --- TLS Imports ---
use tokio_rustls::{
    rustls::{ServerConfig, ServerConnection},
    server::TlsStream,
    TlsAcceptor,
};
use tokio::io::{AsyncRead, AsyncWrite};
// -------------------
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::time::sleep;
use futures::future::Either;
use std::pin::Pin;
use std::task::{Context, Poll};

#[path = "statsd.rs"]
mod statsd;

/// A type alias for either a plain TcpStream or a TlsStream wrapping a TcpStream.
/// This allows the forwarding logic to work with both unencrypted and TLS-encrypted streams.
pub enum TcpLikeStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

// Implement AsyncRead and AsyncWrite for TcpLikeStream so it can be used generically
impl AsyncRead for TcpLikeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            TcpLikeStream::Plain(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
            TcpLikeStream::Tls(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpLikeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            TcpLikeStream::Plain(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
            TcpLikeStream::Tls(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            TcpLikeStream::Plain(ref mut stream) => Pin::new(stream).poll_flush(cx),
            TcpLikeStream::Tls(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            TcpLikeStream::Plain(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
            TcpLikeStream::Tls(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }

     fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            TcpLikeStream::Plain(ref mut stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            TcpLikeStream::Tls(ref mut stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            TcpLikeStream::Plain(stream) => stream.is_write_vectored(),
            TcpLikeStream::Tls(stream) => stream.is_write_vectored(),
        }
    }
}
impl Unpin for TcpLikeStream {}


/// Settings for a tcp2udp session. This is the argument to [`run`] to
/// describe how the forwarding from TCP -> UDP should be set up.
///
/// This struct is `non_exhaustive` in order to allow adding more optional fields without
/// being considered breaking changes. So you need to create an instance via [`Options::new`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[cfg_attr(feature = "clap", group(skip))]
#[non_exhaustive]
pub struct Options {
    /// The IP and TCP port(s) to listen to for incoming traffic from udp2tcp.
    /// Supports binding multiple TCP sockets.
    #[cfg_attr(feature = "clap", arg(long = "tcp-listen", required(true)))]
    pub tcp_listen_addrs: Vec<SocketAddr>,
    #[cfg_attr(feature = "clap", arg(long = "udp-forward"))]
    /// The IP and UDP port to forward all traffic to.
    pub udp_forward_addr: SocketAddr,
    /// Which local IP to bind the UDP socket to.
    #[cfg_attr(feature = "clap", arg(long = "udp-bind"))]
    pub udp_bind_ip: Option<IpAddr>,
    #[cfg_attr(feature = "clap", clap(flatten))]
    pub tcp_options: crate::tcp_options::TcpOptions, // Assumes TcpOptions will be extended with TLS config
    #[cfg(feature = "statsd")]
    /// Host to send statsd metrics to.
    #[cfg_attr(feature = "clap", clap(long))]
    pub statsd_host: Option<SocketAddr>,
}

impl Options {
    /// Creates a new [`Options`] with all mandatory fields set to the passed arguments.
    /// All optional values are set to their default values. They can later be set, since
    /// they are public.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, SocketAddr};
    ///
    /// let mut options = udp_over_tcp::tcp2udp::Options::new(
    ///     // Listen on 127.0.0.1:1234/TCP
    ///     vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234))],
    ///     // Forward to 192.0.2.15:5001/UDP
    ///     SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 15), 5001)),
    /// );
    ///
    /// // Bind the local UDP socket (used to send to 192.0.2.15:5001/UDP) to the loopback interface
    /// options.udp_bind_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    /// ```
    pub fn new(tcp_listen_addrs: Vec<SocketAddr>, udp_forward_addr: SocketAddr) -> Self {
        Options {
            tcp_listen_addrs,
            udp_forward_addr,
            udp_bind_ip: None,
            tcp_options: Default::default(),
            #[cfg(feature = "statsd")]
            statsd_host: None,
        }
    }
}

/// Error returned from [`run`] if something goes wrong.
#[derive(Debug)]
#[non_exhaustive]
pub enum Tcp2UdpError {
    /// No TCP listen addresses given in the `Options`.
    NoTcpListenAddrs,
    CreateTcpSocket(io::Error),
    /// Failed to apply TCP options to socket.
    ApplyTcpOptions(crate::tcp_options::ApplyTcpOptionsError),
    /// Failed to enable `SO_REUSEADDR` on TCP socket
    SetReuseAddr(io::Error),
    /// Failed to bind TCP socket to SocketAddr
    BindTcpSocket(io::Error, SocketAddr),
    /// Failed to start listening on TCP socket
    ListenTcpSocket(io::Error, SocketAddr),
    #[cfg(feature = "statsd")]
    /// Failed to initialize statsd client
    CreateStatsdClient(statsd::Error),
    // --- TLS Errors ---
    /// Failed to initialize TLS configuration
    TlsConfig(String), // Consider using rustls::Error if needed
    /// Failed during TLS handshake
    TlsHandshake(io::Error),
    // ------------------
}

impl fmt::Display for Tcp2UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Tcp2UdpError::*;
        match self {
            NoTcpListenAddrs => "Invalid options, no TCP listen addresses".fmt(f),
            CreateTcpSocket(_) => "Failed to create TCP socket".fmt(f),
            ApplyTcpOptions(_) => "Failed to apply options to TCP socket".fmt(f),
            SetReuseAddr(_) => "Failed to set SO_REUSEADDR on TCP socket".fmt(f),
            BindTcpSocket(_, addr) => write!(f, "Failed to bind TCP socket to {}", addr),
            ListenTcpSocket(_, addr) => write!(
                f,
                "Failed to start listening on TCP socket bound to {}",
                addr
            ),
            #[cfg(feature = "statsd")]
            CreateStatsdClient(_) => "Failed to init metrics client".fmt(f),
            // --- TLS Errors ---
            TlsConfig(msg) => write!(f, "Failed to initialize TLS config: {}", msg),
            TlsHandshake(e) => write!(f, "TLS handshake failed: {}", e),
            // ------------------
        }
    }
}

impl std::error::Error for Tcp2UdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Tcp2UdpError::*;
        match self {
            NoTcpListenAddrs => None,
            CreateTcpSocket(e) => Some(e),
            ApplyTcpOptions(e) => Some(e),
            SetReuseAddr(e) => Some(e),
            BindTcpSocket(e, _) => Some(e),
            ListenTcpSocket(e, _) => Some(e),
            #[cfg(feature = "statsd")]
            CreateStatsdClient(e) => Some(e),
            // --- TLS Errors ---
            TlsConfig(_) => None, // String doesn't implement Error
            TlsHandshake(e) => Some(e),
            // ------------------
        }
    }
}

/// Sets up TCP listening sockets on all addresses in `Options::tcp_listen_addrs`.
/// If binding a listening socket fails this returns an error. Otherwise the function
/// will continue indefinitely to accept incoming connections and forward to UDP.
/// Errors are just logged.
pub async fn run(options: Options) -> Result<Infallible, Tcp2UdpError> {
    if options.tcp_listen_addrs.is_empty() {
        return Err(Tcp2UdpError::NoTcpListenAddrs);
    }

    // --- TLS Setup ---
    let tls_config: Option<Arc<ServerConfig>> = if options.tcp_options.use_tls { // Assuming TcpOptions has use_tls: bool
        // TODO: Load certs and key based on paths in options.tcp_options
        // Example (needs error handling):
        // let certs = load_certs(&options.tcp_options.tls_cert_path)?;
        // let key = load_private_key(&options.tcp_options.tls_key_path)?;
        // let config = ServerConfig::builder()
        //     .with_safe_defaults()
        //     .with_no_client_auth()
        //     .with_single_cert(certs, key)
        //     .map_err(|e| Tcp2UdpError::TlsConfig(format!("Failed to create ServerConfig: {}", e)))?;
        // Some(Arc::new(config))

        // Placeholder: Return an error if TLS is requested but not implemented yet in this stub
        return Err(Tcp2UdpError::TlsConfig("TLS is enabled in options but not yet fully implemented in this stub.".to_string()));
        // Once implemented, replace the above line with the actual config creation.
    } else {
        None
    };
    // -----------------

    let udp_bind_ip = options.udp_bind_ip.unwrap_or_else(|| {
        if options.udp_forward_addr.is_ipv4() {
            "0.0.0.0".parse().unwrap()
        } else {
            "::".parse().unwrap()
        }
    });

    #[cfg(not(feature = "statsd"))]
    let statsd = Arc::new(statsd::StatsdMetrics::dummy());
    #[cfg(feature = "statsd")]
    let statsd = Arc::new(
        match options.statsd_host {
            None => statsd::StatsdMetrics::dummy(),
            Some(statsd_host) => statsd::StatsdMetrics::real(statsd_host)
                .map_err(Tcp2UdpError::CreateStatsdClient)?,
        },
    );

    let mut join_handles = Vec::with_capacity(options.tcp_listen_addrs.len());
    for tcp_listen_addr in options.tcp_listen_addrs {
        let tcp_listener = create_listening_socket(tcp_listen_addr, &options.tcp_options)?;
        log::info!(
            "Listening on {}/TCP{}",
            tcp_listener.local_addr().unwrap(),
            if tls_config.is_some() { " (TLS)" } else { "" } // Log TLS status
        );

        let udp_forward_addr = options.udp_forward_addr;
        let tcp_recv_timeout = options.tcp_options.recv_timeout;
        let tcp_nodelay = options.tcp_options.nodelay;
        let statsd = Arc::clone(&statsd);
        // --- Pass TLS Config ---
        let tls_config_clone = tls_config.clone(); // Clone Arc for the spawned task
        // -----------------------
        join_handles.push(tokio::spawn(async move {
            process_tcp_listener(
                tcp_listener,
                udp_bind_ip,
                udp_forward_addr,
                tcp_recv_timeout,
                tcp_nodelay,
                statsd,
                tls_config_clone, // Pass TLS config
            )
            .await;
        }));
    }

    futures::future::join_all(join_handles).await;
    unreachable!("Listening TCP sockets never exit");
}

fn create_listening_socket(
    addr: SocketAddr,
    options: &crate::tcp_options::TcpOptions,
) -> Result<TcpListener, Tcp2UdpError> {
    let tcp_socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4(),
        SocketAddr::V6(..) => TcpSocket::new_v6(),
    }
    .map_err(Tcp2UdpError::CreateTcpSocket)?;

    crate::tcp_options::apply(&tcp_socket, options).map_err(Tcp2UdpError::ApplyTcpOptions)?;

    tcp_socket
        .set_reuseaddr(true)
        .map_err(Tcp2UdpError::SetReuseAddr)?;

    tcp_socket
        .bind(addr)
        .map_err(|e| Tcp2UdpError::BindTcpSocket(e, addr))?;

    let tcp_listener = tcp_socket
        .listen(1024)
        .map_err(|e| Tcp2UdpError::ListenTcpSocket(e, addr))?;

    Ok(tcp_listener)
}

// --- Modified process_tcp_listener to handle TLS ---
async fn process_tcp_listener(
    tcp_listener: TcpListener,
    udp_bind_ip: IpAddr,
    udp_forward_addr: SocketAddr,
    tcp_recv_timeout: Option<Duration>,
    tcp_nodelay: bool,
    statsd: Arc<statsd::StatsdMetrics>,
    tls_config: Option<Arc<ServerConfig>>, // Accept TLS config
) -> ! {
    let mut cooldown =
        ExponentialBackoff::new(Duration::from_millis(50), Duration::from_millis(5000));

    // --- Create TlsAcceptor if TLS is enabled ---
    let tls_acceptor: Option<TlsAcceptor> = tls_config.map(TlsAcceptor::from);
    // -------------------------------------------

    loop {
        // Accept the raw TCP stream
        let accept_result = tcp_listener.accept().await;
        match accept_result {
            Ok((tcp_stream, tcp_peer_addr)) => {
                log::debug!("Incoming connection from {}/TCP{}", Redact(tcp_peer_addr), if tls_acceptor.is_some() { " (TLS)" } else { "" });

                if let Err(error) = crate::tcp_options::set_nodelay(&tcp_stream, tcp_nodelay) {
                    log::error!("Error setting TCP_NODELAY: {}", error.display("\nCaused by: "));
                }

                let statsd = statsd.clone();
                // --- Clone TLS acceptor for the spawned task ---
                let tls_acceptor_task = tls_acceptor.clone();
                // ---------------------------------------------

                tokio::spawn(async move {
                    statsd.incr_connections();

                    // --- Perform TLS handshake if configured ---
                    let tcp_like_stream: Result<TcpLikeStream, Tcp2UdpError> = if let Some(acceptor) = tls_acceptor_task {
                        match acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                log::debug!("TLS handshake successful for {}/TCP", Redact(tcp_peer_addr));
                                Ok(TcpLikeStream::Tls(tls_stream))
                            },
                            Err(e) => {
                                log::warn!("TLS handshake failed for {}/TCP: {}", Redact(tcp_peer_addr), e);
                                Err(Tcp2UdpError::TlsHandshake(e))
                            }
                        }
                    } else {
                         Ok(TcpLikeStream::Plain(tcp_stream))
                    };
                    // ------------------------------------------

                    match tcp_like_stream {
                         Ok(stream) => {
                            // Pass the potentially TLS-wrapped stream to processing
                            if let Err(error) = process_socket(
                                stream, // Pass TcpLikeStream
                                tcp_peer_addr,
                                udp_bind_ip,
                                udp_forward_addr,
                                tcp_recv_timeout,
                            )
                            .await
                            {
                                log::error!("Error in connection processing: {}", error.display("\nCaused by: "));
                            }
                         },
                         Err(e) => {
                             log::error!("Failed to establish connection stream for {}/TCP: {}", Redact(tcp_peer_addr), e);
                         }
                    }

                    statsd.decr_connections();
                });
                cooldown.reset();
            }
            Err(error) => {
                log::error!("Error when accepting incoming TCP connection: {}", error);
                statsd.accept_error();
                // If the process runs out of file descriptors, it will fail to accept a socket.
                // But that socket will also remain in the queue, so it will fail again immediately.
                // This will busy loop consuming the CPU and filling any logs. To prevent this,
                // delay between failed socket accept operations.
                sleep(cooldown.next_delay()).await;
            }
        }
    }
}
// -------------------------------------------------

/// Sets up a UDP socket bound to `udp_bind_ip` and connected to `udp_peer_addr` and forwards
/// traffic between that UDP socket and the given `tcp_stream` until the `tcp_stream` is closed.
/// `tcp_peer_addr` should be the remote addr that `tcp_stream` is connected to.
/// Accepts a generic stream that implements AsyncRead + AsyncWrite + Unpin (e.g., TcpStream or TlsStream<TcpStream>)
async fn process_socket(
    tcp_stream: TcpLikeStream, // Accept the generic stream type
    tcp_peer_addr: SocketAddr,
    udp_bind_ip: IpAddr,
    udp_peer_addr: SocketAddr,
    tcp_recv_timeout: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error>> {
    let udp_bind_addr = SocketAddr::new(udp_bind_ip, 0);
    let udp_socket = UdpSocket::bind(udp_bind_addr)
        .await
        .with_context(|_| format!("Failed to bind UDP socket to {}", udp_bind_addr))?;

    udp_socket
        .connect(udp_peer_addr)
        .await
        .with_context(|_| format!("Failed to connect UDP socket to {}", udp_peer_addr))?;

    log::debug!(
        "UDP socket bound to {} and connected to {}",
        udp_socket
            .local_addr()
            .ok()
            .as_ref()
            .map(|item| -> &dyn fmt::Display { item })
            .unwrap_or(&"unknown"),
        udp_peer_addr
    );

    // --- Forward traffic using the generic stream ---
    crate::forward_traffic::process_udp_over_tcp(udp_socket, tcp_stream, tcp_recv_timeout).await;
    // -----------------------------------------------

    log::debug!(
        "Closing forwarding for {}/TCP <-> {}/UDP",
        Redact(tcp_peer_addr),
        udp_peer_addr
    );
    Ok(())
}

// TODO: Implement helper functions like load_certs and load_private_key in bin/tcp2udp.rs or a shared utility module
// Example sketch (needs proper error handling and file reading):
// fn load_certs(path: &str) -> Result<Vec<rustls::Certificate>, Box<dyn std::error::Error>> { ... }
// fn load_private_key(path: &str) -> Result<rustls::PrivateKey, Box<dyn std::error::Error>> { ... }

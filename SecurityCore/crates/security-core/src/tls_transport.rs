//! Pure-Rust TLS transport for future remote log shipping (SIEM/collector).
//!
//! Uses rustls — no OpenSSL dependency, no CVE surface from C code.
//! This module provides connection setup; actual log shipping protocols
//! (syslog-TLS, HTTPS POST, etc.) are built on top.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// TLS connection configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub host: String,
    pub port: u16,
    pub connect_timeout: Duration,
}

impl TlsConfig {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}

/// An established TLS connection.
pub struct TlsConnection {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

impl TlsConnection {
    /// Establish a TLS connection to the configured host.
    pub fn connect(config: &TlsConfig) -> Result<Self, TlsError> {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = rustls::pki_types::ServerName::try_from(config.host.as_str())
            .map_err(|e| TlsError::ConnectionFailed(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tls_conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
            .map_err(|e| TlsError::ConnectionFailed(format!("TLS init: {}", e)))?;

        let addr = format!("{}:{}", config.host, config.port);
        let tcp = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| TlsError::ConnectionFailed(format!("Address parse: {}", e)))?,
            config.connect_timeout,
        )
        .map_err(|e| TlsError::ConnectionFailed(format!("TCP connect: {}", e)))?;

        let stream = rustls::StreamOwned::new(tls_conn, tcp);

        Ok(Self { stream })
    }

    /// Send data over the TLS connection.
    pub fn send(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.stream
            .write_all(data)
            .map_err(|e| TlsError::SendFailed(format!("{}", e)))?;
        self.stream
            .flush()
            .map_err(|e| TlsError::SendFailed(format!("flush: {}", e)))?;
        Ok(())
    }

    /// Send a line (appends \n).
    pub fn send_line(&mut self, line: &str) -> Result<(), TlsError> {
        self.send(line.as_bytes())?;
        self.send(b"\n")
    }

    /// Read response (up to max_bytes).
    pub fn read_response(&mut self, max_bytes: usize) -> Result<Vec<u8>, TlsError> {
        let mut buf = vec![0u8; max_bytes];
        let n = self
            .stream
            .read(&mut buf)
            .map_err(|e| TlsError::ReadFailed(format!("{}", e)))?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// TLS transport errors.
#[derive(Debug)]
pub enum TlsError {
    ConnectionFailed(String),
    SendFailed(String),
    ReadFailed(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "TLS connection failed: {}", msg),
            Self::SendFailed(msg) => write!(f, "TLS send failed: {}", msg),
            Self::ReadFailed(msg) => write!(f, "TLS read failed: {}", msg),
        }
    }
}

impl std::error::Error for TlsError {}

/// Future: Log shipper that sends JSON alerts over TLS.
/// Placeholder for Phase 6 integration with SIEM/collectors.
pub struct LogShipper {
    config: TlsConfig,
}

impl LogShipper {
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Ship a single JSON alert line. Opens a new connection per call.
    /// For production, this should use connection pooling.
    pub fn ship_alert(&self, json_line: &str) -> Result<(), TlsError> {
        let mut conn = TlsConnection::connect(&self.config)?;
        conn.send_line(json_line)?;
        Ok(())
    }

    pub fn config(&self) -> &TlsConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_builder() {
        let config = TlsConfig::new("logs.example.com", 6514)
            .with_timeout(Duration::from_secs(5));

        assert_eq!(config.host, "logs.example.com");
        assert_eq!(config.port, 6514);
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn log_shipper_creation() {
        let config = TlsConfig::new("siem.internal", 443);
        let shipper = LogShipper::new(config);
        assert_eq!(shipper.config().host, "siem.internal");
        assert_eq!(shipper.config().port, 443);
    }

    // Note: actual TLS connection tests require a live server.
    // Integration tests would use a local TLS echo server.
}

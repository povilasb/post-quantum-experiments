use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;


fn main() {
    env_logger::init();

    rustls_post_quantum::provider()
        .install_default()
        .unwrap();

    // For this example, we'll use a dangerous configuration that doesn't verify
    // the server certificate. This is only acceptable for local testing!
    // For a real application, you would use proper certificates!
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
        .with_no_client_auth();

    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("127.0.0.1:8443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    // Send HTTP request
    tls.write_all(
        concat!(
            "GET / HTTP/1.0\r\n",
            "Host: localhost\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    // Print connection info
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    println!("Client negotiated cipher suite: {:?}", ciphersuite.suite());

    let kx_group = tls
        .conn
        .negotiated_key_exchange_group()
        .unwrap();
    println!("Client negotiated key exchange group: {:?}", kx_group);
    println!();

    // Read and print response
    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => (),
        Err(e) => eprintln!("Error reading from server: {:?}", e),
    }
    println!("Response from server:");
    println!("{}", String::from_utf8_lossy(&plaintext));
}

// DANGER: This is only for testing with self-signed certificates!
// Never use this in production code!
#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Skip all verification - DANGEROUS!
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

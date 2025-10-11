use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::pki_types::PrivateKeyDer;

fn main() {
    env_logger::init();

    // Install the post-quantum crypto provider
    rustls_post_quantum::provider()
        .install_default()
        .unwrap();

    // Generate a self-signed certificate for the server
    let cert_key_pair = generate_self_signed_cert();
    let certs = vec![cert_key_pair.cert];
    let private_key = cert_key_pair.key;

    // Create server configuration
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("bad certificate/key");

    let listener = TcpListener::bind("127.0.0.1:8443").unwrap();
    println!("Server listening on https://127.0.0.1:8443");
    println!("Connect with: cargo run --bin client");
    println!();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let config = Arc::clone(&Arc::new(config.clone()));

                println!("Accepted connection from: {}", stream.peer_addr().unwrap());

                let mut conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);

                // Read the HTTP request
                let mut request = vec![0u8; 4096];
                match tls.read(&mut request) {
                    Ok(n) if n > 0 => {
                        // Print negotiated parameters
                        let ciphersuite = tls
                            .conn
                            .negotiated_cipher_suite()
                            .unwrap();
                        println!("  Cipher suite: {:?}", ciphersuite.suite());

                        if let Some(kx_group) = tls.conn.negotiated_key_exchange_group() {
                            println!("  Key exchange group: {:?}", kx_group);
                        }

                        // Send HTTP response
                        let response_body = format!(
                            "TLS Connection Established!\n\n\
                             Cipher Suite: {:?}\n\
                             Key Exchange: {:?}\n\n\
                             This server is using rustls-post-quantum for post-quantum cryptography.\n",
                            ciphersuite.suite(),
                            tls.conn.negotiated_key_exchange_group()
                        );

                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {}",
                            response_body.len(),
                            response_body
                        );

                        tls.write_all(response.as_bytes()).unwrap();
                        println!("  Response sent\n");
                    }
                    Ok(_) => println!("  Client closed connection before sending data\n"),
                    Err(e) => eprintln!("  Error reading from client: {}\n", e),
                }
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}

struct CertKeyPair {
    cert: rustls::pki_types::CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn generate_self_signed_cert() -> CertKeyPair {
    use rcgen::{CertificateParams, KeyPair};

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

    let params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ]).unwrap();

    let cert = params.self_signed(&key_pair).unwrap();

    CertKeyPair {
        cert: cert.der().clone(),
        key: PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap(),
    }
}

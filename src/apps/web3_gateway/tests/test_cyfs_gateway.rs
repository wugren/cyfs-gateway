#[cfg(test)]
mod tests {
    use async_compression::tokio::bufread::GzipDecoder;
    use buckyos_kit::init_logging;
    use bytes::Bytes;
    use web3_gateway::{
        gateway_service_main, read_login_token, GatewayControlClient, GatewayParams, CONTROL_SERVER,
    };
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    use http_body_util::BodyExt;
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;
    use serde_json::json;
    use std::collections::HashSet;
    use std::io::Cursor;
    use std::net::{IpAddr, SocketAddr};
    use std::path::Path;
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn gunzip_bytes(data: Bytes) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut decoder = GzipDecoder::new(reader);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DecodedIoDumpFrame {
        upload: Vec<u8>,
        download: Vec<u8>,
    }

    fn decode_io_dump_frames(mut data: &[u8]) -> Result<Vec<DecodedIoDumpFrame>, String> {
        let mut frames = Vec::new();
        while !data.is_empty() {
            if data.len() < 9 {
                return Err("truncated frame header".to_string());
            }
            if &data[0..4] != b"CGDP" {
                return Err("invalid frame magic".to_string());
            }
            if data[4] != 1 {
                return Err(format!("unsupported frame version: {}", data[4]));
            }
            let frame_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
            if frame_len < 9 || frame_len > data.len() {
                return Err("invalid frame length".to_string());
            }
            let frame = &data[9..frame_len];
            let mut offset = 0usize;

            fn take<'a>(buf: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], String> {
                if *offset + len > buf.len() {
                    return Err("truncated frame payload".to_string());
                }
                let part = &buf[*offset..*offset + len];
                *offset += len;
                Ok(part)
            }

            let _ = take(frame, &mut offset, 8)?;
            let _ = take(frame, &mut offset, 8)?;

            let src_len =
                u16::from_le_bytes(take(frame, &mut offset, 2)?.try_into().unwrap()) as usize;
            let _ = take(frame, &mut offset, src_len)?;

            let dst_len =
                u16::from_le_bytes(take(frame, &mut offset, 2)?.try_into().unwrap()) as usize;
            let _ = take(frame, &mut offset, dst_len)?;

            let upload_len =
                u32::from_le_bytes(take(frame, &mut offset, 4)?.try_into().unwrap()) as usize;
            let upload = take(frame, &mut offset, upload_len)?.to_vec();

            let download_len =
                u32::from_le_bytes(take(frame, &mut offset, 4)?.try_into().unwrap()) as usize;
            let download = take(frame, &mut offset, download_len)?.to_vec();

            frames.push(DecodedIoDumpFrame { upload, download });
            data = &data[frame_len..];
        }
        Ok(frames)
    }

    async fn wait_dump_frames(file: &Path, min_frames: usize) -> Vec<DecodedIoDumpFrame> {
        for _ in 0..80 {
            if let Ok(data) = std::fs::read(file) {
                if !data.is_empty() {
                    if let Ok(frames) = decode_io_dump_frames(&data) {
                        if frames.len() >= min_frames {
                            return frames;
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("io dump frames not ready");
    }
    const SOCKS_VERSION: u8 = 0x05;
    const SOCKS_AUTH_NONE: u8 = 0x00;
    const SOCKS_AUTH_USERNAME_PASSWORD: u8 = 0x02;
    const SOCKS_CMD_CONNECT: u8 = 0x01;
    const SOCKS_ADDR_IPV4: u8 = 0x01;
    const SOCKS_ADDR_DOMAIN: u8 = 0x03;
    const SOCKS_ADDR_IPV6: u8 = 0x04;
    const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;

    #[derive(Debug)]
    enum SocksClientError {
        Io(std::io::Error),
        InvalidReply(&'static str),
        AuthFailed(u8),
        ConnectFailed(u8),
    }

    impl From<std::io::Error> for SocksClientError {
        fn from(e: std::io::Error) -> Self {
            Self::Io(e)
        }
    }

    impl std::fmt::Display for SocksClientError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                SocksClientError::Io(e) => write!(f, "io error: {}", e),
                SocksClientError::InvalidReply(msg) => write!(f, "invalid reply: {}", msg),
                SocksClientError::AuthFailed(code) => write!(f, "auth failed, code={}", code),
                SocksClientError::ConnectFailed(code) => {
                    write!(f, "connect failed, code={}", code)
                }
            }
        }
    }

    async fn allocate_free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn wait_for_tcp(addr: SocketAddr) {
        for _ in 0..80 {
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("server did not start on {}", addr);
    }

    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };

                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(_) => break,
                        };

                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        port
    }

    async fn read_socks_addr(stream: &mut TcpStream, atyp: u8) -> Result<(), std::io::Error> {
        match atyp {
            SOCKS_ADDR_IPV4 => {
                let mut rest = [0u8; 6];
                stream.read_exact(&mut rest).await?;
            }
            SOCKS_ADDR_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut rest = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut rest).await?;
            }
            SOCKS_ADDR_IPV6 => {
                let mut rest = [0u8; 18];
                stream.read_exact(&mut rest).await?;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid addr type",
                ));
            }
        }

        Ok(())
    }

    async fn socks5_connect(
        socks_addr: &str,
        username: &str,
        password: &str,
        target_port: u16,
    ) -> Result<TcpStream, SocksClientError> {
        let mut stream = TcpStream::connect(socks_addr).await?;

        stream
            .write_all(&[
                SOCKS_VERSION,
                2,
                SOCKS_AUTH_NONE,
                SOCKS_AUTH_USERNAME_PASSWORD,
            ])
            .await?;

        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply).await?;
        if method_reply[0] != SOCKS_VERSION {
            return Err(SocksClientError::InvalidReply(
                "invalid method reply version",
            ));
        }
        if method_reply[1] != SOCKS_AUTH_USERNAME_PASSWORD {
            return Err(SocksClientError::InvalidReply(
                "server did not choose username/password method",
            ));
        }

        let mut auth_req = vec![0x01, username.len() as u8];
        auth_req.extend_from_slice(username.as_bytes());
        auth_req.push(password.len() as u8);
        auth_req.extend_from_slice(password.as_bytes());
        stream.write_all(&auth_req).await?;

        let mut auth_reply = [0u8; 2];
        stream.read_exact(&mut auth_reply).await?;
        if auth_reply[0] != 0x01 {
            return Err(SocksClientError::InvalidReply("invalid auth reply version"));
        }
        if auth_reply[1] != 0x00 {
            return Err(SocksClientError::AuthFailed(auth_reply[1]));
        }

        let mut req = vec![
            SOCKS_VERSION,
            SOCKS_CMD_CONNECT,
            0x00,
            SOCKS_ADDR_IPV4,
            127,
            0,
            0,
            1,
        ];
        req.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut reply_head = [0u8; 4];
        stream.read_exact(&mut reply_head).await?;
        if reply_head[0] != SOCKS_VERSION {
            return Err(SocksClientError::InvalidReply(
                "invalid connect reply version",
            ));
        }

        read_socks_addr(&mut stream, reply_head[3]).await?;
        if reply_head[1] != SOCKS_REPLY_SUCCEEDED {
            return Err(SocksClientError::ConnectFailed(reply_head[1]));
        }

        Ok(stream)
    }

    #[tokio::test]
    async fn test_cyfs_gateway() {
        init_logging("test_cyfs_gateway", false);
        let root_dir = tempfile::TempDir::new().unwrap();
        unsafe {
            std::env::set_var(
                "BUCKYOS_ROOT",
                root_dir.path().to_string_lossy().to_string(),
            );
        }

        let gateway_socks_user = "gateway_user";
        let gateway_socks_pass = "gateway_pass";
        let upstream_socks_user = "upstream_user";
        let upstream_socks_pass = "upstream_pass";

        let echo_direct_port = start_echo_server().await;
        let echo_proxy_port = start_echo_server().await;
        let reject_port = allocate_free_port().await;
        let socks_stack_port = allocate_free_port().await;
        let upstream_socks_stack_port = allocate_free_port().await;
        let control_server_port = allocate_free_port().await;
        let control_server = format!("http://127.0.0.1:{control_server_port}");

        let config = include_str!("test_cyfs_gateway.yaml");
        let local_dns = include_str!("local_dns.toml");
        let config_file = tempfile::NamedTempFile::with_suffix(".yaml").unwrap();
        let local_dns_file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(local_dns_file.path(), local_dns).unwrap();
        let config = config.replace("{{local_dns}}", local_dns_file.path().to_str().unwrap());

        let json_set = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        let json_set_path = json_set.path().to_path_buf();
        let config = config.replace("{{test_json_set}}", json_set_path.to_str().unwrap());

        let json_map = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        let config = config.replace("{{test_json_map}}", json_map.path().to_str().unwrap());

        let sqlite_set = tempfile::NamedTempFile::with_suffix(".sqlite").unwrap();
        let config = config.replace("{{test_sqlite_set}}", sqlite_set.path().to_str().unwrap());

        let sqlite_map = tempfile::NamedTempFile::with_suffix(".sqlite").unwrap();
        let config = config.replace("{{test_sqlite_map}}", sqlite_map.path().to_str().unwrap());

        let text_set = tempfile::NamedTempFile::with_suffix(".txt").unwrap();
        let config = config.replace("{{test_text_set}}", text_set.path().to_str().unwrap());

        let js_hook_file = tempfile::NamedTempFile::with_suffix(".js").unwrap();
        let js_hook = r#"
function test_js_hook(context, host) {
    console.log(`Checking host: ${host}`);
    return true;
}
"#;
        std::fs::write(js_hook_file.path(), js_hook).unwrap();
        let config = config.replace(
            "{{test_js_hook_file}}",
            js_hook_file.path().to_str().unwrap(),
        );

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let config = config.replace("{{sn_db}}", db.path().to_str().unwrap());

        let io_dump = tempfile::NamedTempFile::with_suffix(".dump").unwrap();
        let config = config.replace("{{test_io_dump}}", io_dump.path().to_str().unwrap());

        let local_dir = tempfile::TempDir::new().unwrap();
        let config = config.replace("{{web3_dir}}", local_dir.path().to_str().unwrap());
        let path = local_dir.path().join("index.html");
        std::fs::write(path, "web3.buckyos.com").unwrap();
        let path = local_dir.path().join("test.txt");
        std::fs::write(path, "test").unwrap();

        let local_dir = tempfile::TempDir::new().unwrap();
        let config = config.replace("{{www_dir}}", local_dir.path().to_str().unwrap());
        let path = local_dir.path().join("index.html");
        std::fs::write(path, "www.buckyos.com").unwrap();

        let path = local_dir.path().join("index2.html");
        let raw_compress_body = "www.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.com";
        std::fs::write(path, raw_compress_body).unwrap();
        let config = config.replace(
            "{{socks_stack_port}}",
            socks_stack_port.to_string().as_str(),
        );
        let config = config.replace("{{socks_user}}", gateway_socks_user);
        let config = config.replace("{{socks_pass}}", gateway_socks_pass);
        let config = config.replace("{{upstream_socks_user}}", upstream_socks_user);
        let config = config.replace("{{upstream_socks_pass}}", upstream_socks_pass);
        let config = config.replace(
            "{{upstream_socks_stack_port}}",
            upstream_socks_stack_port.to_string().as_str(),
        );
        let config = config.replace(
            "{{control_server_port}}",
            control_server_port.to_string().as_str(),
        );
        let config = config.replace(
            "{{echo_direct_port}}",
            echo_direct_port.to_string().as_str(),
        );
        let config = config.replace("{{echo_proxy_port}}", echo_proxy_port.to_string().as_str());

        std::fs::write(config_file.path(), config).unwrap();

        tokio::spawn(async move {
            gateway_service_main(
                config_file.path(),
                GatewayParams {
                    keep_tunnel: vec![],
                },
            )
            .await
            .unwrap();
        });

        wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], 18080))).await;

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "web3.buckyos.com".len()).as_str()
            );
            assert_eq!(response.headers().get("x-test").unwrap(), "1");
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"web3.buckyos.com");

            let frames = wait_dump_frames(io_dump.path(), 1).await;
            assert!(frames.iter().any(|f| {
                f.upload.starts_with(b"GET /") && f.download.starts_with(b"HTTP/1.1")
            }));

            let request = hyper::Request::get("/test.txt")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "test".len()).as_str()
            );
            assert_eq!(response.headers().get("x-test").unwrap(), "1");
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"test");
        }

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "www.buckyos.com".len()).as_str()
            );
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/index2.html")
                .header("Host", "www.buckyos.com")
                .header("Accept-Encoding", "gzip")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert!(response.headers().get("content-encoding").is_some());
            assert_eq!(
                response
                    .headers()
                    .get("content-encoding")
                    .map(|v| v.to_str().unwrap()),
                Some("gzip")
            );
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            let decoded = gunzip_bytes(data.to_bytes()).await;
            assert_eq!(decoded.as_ref(), raw_compress_body.as_bytes());
        }

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/index2.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert!(response.headers().get("content-encoding").is_none());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), raw_compress_body.as_bytes());
        }

        {
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/api/")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "www.buckyos.com".len()).as_str()
            );
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/test_return/")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "web3.buckyos.com".len()).as_str()
            );
            // assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "www.buckyos.com".len()).as_str());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"web3.buckyos.com");
            // assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let body = json!({
                "method": "admin.clear_state_by_active_code",
                "params": {
                    "username": "test",
                },
                "sys": [1]
            });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(
                    serde_json::to_string(&body).unwrap().as_bytes().to_vec(),
                )))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18084")
                .await
                .unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "ptcp-direct.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let source_port = allocate_free_port().await;
            let source_addr = SocketAddr::from(([127, 0, 0, 1], source_port));
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind(source_addr).unwrap();
            let stream = socket
                .connect(SocketAddr::from_str("127.0.0.1:18082").unwrap())
                .await
                .unwrap();
            let expected_port = source_port;

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "ptcp-probe.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);

            let remote_port = response
                .headers()
                .get("x-remote-port")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap();
            let conn_remote_port = response
                .headers()
                .get("x-conn-remote-port")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap();
            let real_remote_port = response
                .headers()
                .get("x-real-remote-port")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap();

            assert_eq!(remote_port, expected_port);
            assert_eq!(real_remote_port, expected_port);
            assert_ne!(conn_remote_port, expected_port);

            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let name_server_configs = vec![NameServerConfig::new(
                SocketAddr::from_str("127.0.0.1:9545").unwrap(),
                Protocol::Udp,
            )];
            let server_config = ResolverConfig::from_parts(None, vec![], name_server_configs);
            let resolver = TokioAsyncResolver::tokio(server_config, ResolverOpts::default());
            let response = resolver.lookup_ip("www.buckyos.com.").await;
            assert!(response.is_ok());
            let ips = response.unwrap().iter().collect::<Vec<_>>();
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], IpAddr::from_str("192.168.1.1").unwrap());

            let response = resolver.txt_lookup("www.buckyos.com.").await;
            assert!(response.is_ok());
            let ips = response
                .unwrap()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>();
            assert_eq!(ips.len(), 3);

            let response = resolver.lookup_ip("web3.buckyos.com.").await;
            assert!(response.is_ok());
            let ips = response.unwrap().iter().collect::<Vec<_>>();
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], IpAddr::from_str("192.168.1.2").unwrap());
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client.add_rule("stack:test1", r#"http_probe && eq ${REQ.dest_host} "test.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_err());
            let ret = cyfs_cmd_client.add_rule("stack1:test1", r#"http-probe && eq ${REQ.dest_host} "test.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_err());
            let ret = cyfs_cmd_client.add_rule("stack:test1", r#"http-probe && eq ${REQ.dest_host} "test.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "test.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "www.buckyos.com".len()).as_str()
            );
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client.add_rule("stack:test1", r#"http-probe && eq ${REQ.dest_host} "test2.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "www.buckyos.com".len()).as_str()
            );
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client.add_rule("server:www.buckyos.com:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_ok());

            let ret = cyfs_cmd_client.add_rule("server:www_dir:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let body = json!({
                "method": "admin.clear_state_by_active_code",
                "params": {
                    "username": "test",
                },
                "sys": [1]
            });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(
                    serde_json::to_string(&body).unwrap().as_bytes().to_vec(),
                )))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client
                .remove_rule("server:www.buckyos.com:main:test2")
                .await;
            assert!(ret.is_ok());

            let ret = cyfs_cmd_client
                .remove_rule("server:www.buckyos.com:main:test2")
                .await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let body = json!({
                "method": "admin.clear_state_by_active_code",
                "params": {
                    "username": "test",
                },
                "sys": [1]
            });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(
                    serde_json::to_string(&body).unwrap().as_bytes().to_vec(),
                )))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::METHOD_NOT_ALLOWED);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client.append_rule("server:www.buckyos.com:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_ok());

            let ret = cyfs_cmd_client.append_rule("server:www_dir:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let body = json!({
                "method": "admin.clear_state_by_active_code",
                "params": {
                    "username": "test",
                },
                "sys": [1]
            });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(
                    serde_json::to_string(&body).unwrap().as_bytes().to_vec(),
                )))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::METHOD_NOT_ALLOWED);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client
                .move_rule("server:www.buckyos.com:main:test2", -1)
                .await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let body = json!({
                "method": "admin.clear_state_by_active_code",
                "params": {
                    "username": "test",
                },
                "sys": [1]
            });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(
                    serde_json::to_string(&body).unwrap().as_bytes().to_vec(),
                )))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client.set_rule("server:www.buckyos.com:main:test2", r#"starts-with ${REQ.path} "/snsn" && rewrite ${REQ.path} "/snsn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let body = json!({
                "method": "admin.clear_state_by_active_code",
                "params": {
                    "username": "test",
                },
                "sys": [1]
            });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::post("/snsn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(
                    serde_json::to_string(&body).unwrap().as_bytes().to_vec(),
                )))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        let router_dir = tempfile::TempDir::new().unwrap();
        {
            let router_target = format!("{}/", router_dir.path().to_string_lossy());
            std::fs::write(router_dir.path().join("index.html"), "router").unwrap();

            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client
                .add_router(
                    Some("server:www.buckyos.com"),
                    "/router/",
                    router_target.as_str(),
                )
                .await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/router/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "router".len()).as_str()
            );
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"router");

            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client
                .remove_router(
                    Some("server:www.buckyos.com"),
                    "/router/",
                    router_target.as_str(),
                )
                .await;
            assert!(ret.is_ok());
            let ret = cyfs_cmd_client
                .remove_router(
                    Some("server:www.buckyos.com"),
                    "/router/",
                    router_target.as_str(),
                )
                .await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/router/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client
                .add_router(
                    Some("server:www.buckyos.com"),
                    "/reverse/",
                    "http://127.0.0.1:18081/",
                )
                .await;
            ret.as_ref().unwrap();
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/reverse/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(
                response.headers().get("content-length").unwrap(),
                format!("{}", "www.buckyos.com".len()).as_str()
            );
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");

            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client
                .remove_router(
                    Some("server:www.buckyos.com"),
                    "/reverse/",
                    "http://127.0.0.1:18081/",
                )
                .await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080")
                .await
                .unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::get("/reverse/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new()))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client
                .add_dispatch("19080", "127.0.0.1:18080", None)
                .await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:19080")
                .await
                .unwrap();

            let body = json!({
                "method": "admin.clear_state_by_active_code",
                "params": {
                    "username": "test",
                },
                "sys": [1]
            });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            let request = hyper::Request::post("/snsn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(
                    serde_json::to_string(&body).unwrap().as_bytes().to_vec(),
                )))
                .unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(
                control_server.as_str(),
                read_login_token(CONTROL_SERVER),
            );
            let ret = cyfs_cmd_client.remove_dispatch("19080", None).await;
            assert!(ret.is_ok());

            let ret = tokio::net::TcpStream::connect("127.0.0.1:19080").await;
            assert!(ret.is_err());
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let ret = socks5_connect(
                format!("127.0.0.1:{}", socks_stack_port).as_str(),
                gateway_socks_user,
                "wrong_password",
                echo_direct_port,
            )
            .await;
            assert!(matches!(ret, Err(SocksClientError::AuthFailed(_))));
        })
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut stream = socks5_connect(
                format!("127.0.0.1:{}", socks_stack_port).as_str(),
                gateway_socks_user,
                gateway_socks_pass,
                echo_direct_port,
            )
            .await
            .unwrap();
            let payload = b"socks-direct";
            stream.write_all(payload).await.unwrap();
            let mut recv = vec![0u8; payload.len()];
            stream.read_exact(&mut recv).await.unwrap();
            assert_eq!(recv.as_slice(), payload);
        })
        .await
        .unwrap();

        let json_set_content = std::fs::read_to_string(&json_set_path).unwrap_or_default();
        if !json_set_content.is_empty() {
            let set: HashSet<String> = serde_json::from_str(json_set_content.as_str()).unwrap();
            assert!(!set.contains("upstream_socks_hit"));
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let ret = socks5_connect(
                format!("127.0.0.1:{}", socks_stack_port).as_str(),
                gateway_socks_user,
                gateway_socks_pass,
                reject_port,
            )
            .await;

            match ret {
                Err(SocksClientError::ConnectFailed(code)) => {
                    assert_eq!(code, 0x04);
                }
                _ => panic!("expected socks connect failure"),
            }
        })
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut stream = socks5_connect(
                format!("127.0.0.1:{}", socks_stack_port).as_str(),
                gateway_socks_user,
                gateway_socks_pass,
                echo_proxy_port,
            )
            .await
            .unwrap();
            let payload = b"socks-proxy";
            stream.write_all(payload).await.unwrap();
            let mut recv = vec![0u8; payload.len()];
            stream.read_exact(&mut recv).await.unwrap();
            assert_eq!(recv.as_slice(), payload);
        })
        .await
        .unwrap();

        let json_set_content = std::fs::read_to_string(&json_set_path).unwrap_or_default();
        assert!(!json_set_content.is_empty());
        let set: HashSet<String> = serde_json::from_str(json_set_content.as_str()).unwrap();
        assert!(set.contains("upstream_socks_hit"));
    }
}

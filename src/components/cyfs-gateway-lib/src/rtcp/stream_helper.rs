use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio::time::{Duration, timeout};

// Stream establishment lifecycle constants.
// Protocol requirement: a waiting-for-HelloStream entry MUST be reclaimed
// within this duration, regardless of whether the peer ever sends HelloStream.
pub const STREAM_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) enum WaitStream {
    Waiting,
    OK(TcpStream),
}

impl WaitStream {
    fn unwrap(self) -> TcpStream {
        match self {
            WaitStream::OK(stream) => stream,
            _ => panic!("unwrap WaitStream error"),
        }
    }
}

#[derive(Clone)]
pub struct RTcpStreamBuildHelper {
    notify_ropen_stream: Arc<Notify>,
    wait_ropen_stream_map: Arc<Mutex<HashMap<String, WaitStream>>>,
}

impl RTcpStreamBuildHelper {
    pub fn new() -> Self {
        RTcpStreamBuildHelper {
            notify_ropen_stream: Arc::new(Notify::new()),
            wait_ropen_stream_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Deliver an incoming HelloStream to the waiter. If no waiter is
    /// registered (either never registered, or already reclaimed by timeout),
    /// the late stream is shut down — the protocol requires the initiator
    /// to have given up by now.
    pub async fn notify_ropen_stream(&self, mut stream: TcpStream, key: &str) {
        let mut wait_streams = self.wait_ropen_stream_map.lock().await;
        let wait_session = wait_streams.get_mut(key);
        if wait_session.is_none() {
            let clone_map: Vec<String> = wait_streams.keys().cloned().collect();
            error!(
                "No wait session for {} (late or unknown HelloStream), map is {:?}",
                key, clone_map
            );

            let _ = stream.shutdown().await;

            return;
        }

        // bind stream to session and notify
        let wait_session = wait_session.unwrap();
        *wait_session = WaitStream::OK(stream);

        self.notify_ropen_stream.notify_waiters();
    }

    pub async fn new_wait_stream(&self, key: &str) {
        let mut map = self.wait_ropen_stream_map.lock().await;
        if let Some(_ret) = map.insert(key.to_string(), WaitStream::Waiting) {
            // FIXME: should we return error here?
            error!("new_wait_stream: key {} already exists", key);
        }
    }

    /// Force-remove a waiting entry. Safe to call even if the entry is
    /// absent (e.g. already delivered). Used on the initiator side to
    /// release the slot when building a stream is aborted before
    /// `wait_ropen_stream` is reached (e.g. send failure, outer timeout).
    pub async fn remove_wait_stream(&self, key: &str) {
        let mut map = self.wait_ropen_stream_map.lock().await;
        map.remove(key);
    }

    pub async fn wait_ropen_stream(&self, key: &str) -> Result<TcpStream, std::io::Error> {
        self.wait_ropen_stream_with_timeout(key, STREAM_WAIT_TIMEOUT)
            .await
    }

    pub async fn wait_ropen_stream_with_timeout(
        &self,
        key: &str,
        timeout_duration: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        let start_time = std::time::Instant::now();

        loop {
            if start_time.elapsed() >= timeout_duration {
                warn!(
                    "Timeout: ropen stream {} was not found within the time limit.",
                    key
                );
                // Protocol requirement: always reclaim the slot on timeout so
                // the waiting table cannot grow unboundedly under a peer that
                // initiates streams and lets them expire.
                self.wait_ropen_stream_map.lock().await.remove(key);
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timeout"));
            }

            {
                let mut map = self.wait_ropen_stream_map.lock().await;
                if let Some(wait_stream) = map.remove(key) {
                    match wait_stream {
                        WaitStream::OK(stream) => {
                            return Ok(stream);
                        }
                        WaitStream::Waiting => {
                            // 重新插入等待状态，继续等待
                            map.insert(key.to_owned(), WaitStream::Waiting);
                        }
                    }
                } else {
                    // Entry was removed externally (e.g. by remove_wait_stream).
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "wait stream entry removed",
                    ));
                }
            }

            let Some(remaining_time) = timeout_duration.checked_sub(start_time.elapsed()) else {
                warn!(
                    "Timeout: ropen stream {} was not found within the time limit.",
                    key
                );
                self.wait_ropen_stream_map.lock().await.remove(key);
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timeout"));
            };
            let check_interval = std::cmp::min(STREAM_WAIT_POLL_INTERVAL, remaining_time);

            if let Err(_) = timeout(check_interval, self.notify_ropen_stream.notified()).await {
                continue;
            }
        }
    }
}

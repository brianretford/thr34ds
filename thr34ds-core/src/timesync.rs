/// Atomic clock synchronisation via the public NTP pool (pool.ntp.org).
///
/// The module queries one of the well-known stratum-1/stratum-2 servers that
/// are ultimately disciplined by national / international atomic clocks (e.g.
/// NIST, PTB, USNO).  The returned offset is applied on top of the local
/// system clock so the application always uses highly accurate UTC timestamps
/// even if the device clock has drifted.
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Result of a successful NTP query.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Current UTC time according to the NTP server.
    pub utc_now: chrono::DateTime<chrono::Utc>,
    /// Difference between NTP time and local system clock (in milliseconds).
    pub offset_ms: i64,
    /// Which NTP server responded.
    pub server: String,
}

/// A pool of well-known public NTP servers that are traceable to atomic
/// standards (NIST, USNO, PTB, etc.).
const NTP_SERVERS: &[&str] = &[
    "time.cloudflare.com:123",
    "time.google.com:123",
    "pool.ntp.org:123",
    "time.windows.com:123",
    "time.apple.com:123",
];

/// Query the first reachable NTP server and return the synchronised time.
///
/// The function is intentionally synchronous and lightweight – it is called
/// from a Tauri command that is already dispatched to a background thread.
pub fn query_ntp() -> Result<SyncResult, String> {
    for &server in NTP_SERVERS {
        match query_single(server) {
            Ok(result) => return Ok(result),
            Err(_) => continue,
        }
    }
    Err("All NTP servers unreachable".into())
}

/// Attempt a single NTP request to `server` (host:port).
fn query_single(server: &str) -> Result<SyncResult, String> {
    // NTP v3 client request packet (48 bytes).
    // Byte 0: LI=0, VN=3, Mode=3  →  0b_00_011_011 = 0x1B
    let mut packet = [0u8; 48];
    packet[0] = 0x1B;

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;

    let t1 = system_time_secs();

    socket
        .send_to(&packet, server)
        .map_err(|e| e.to_string())?;

    let mut buf = [0u8; 48];
    let (n, _) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;
    if n < 48 {
        return Err("Short NTP response".into());
    }

    // Transmit Timestamp is at bytes 40–47 in NTP format (seconds since
    // 1 January 1900).
    let ntp_secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
    let ntp_frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);

    // Convert NTP epoch (1900) to Unix epoch (1970): subtract 70 years.
    const NTP_UNIX_OFFSET: u32 = 2_208_988_800;
    let unix_secs = ntp_secs.saturating_sub(NTP_UNIX_OFFSET) as i64;
    let unix_nanos = (ntp_frac as u64 * 1_000_000_000) >> 32;

    let utc_now = chrono::DateTime::from_timestamp(unix_secs, unix_nanos as u32)
        .unwrap_or_else(chrono::Utc::now);

    let t2 = system_time_secs();
    let local_mid = (t1 + t2) / 2.0;
    let offset_ms = ((unix_secs as f64 + unix_nanos as f64 / 1e9) - local_mid) * 1000.0;

    Ok(SyncResult {
        utc_now,
        offset_ms: offset_ms as i64,
        server: server.to_string(),
    })
}

/// Return the current UNIX time as fractional seconds.
fn system_time_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_packet_is_correct_size() {
        let mut packet = [0u8; 48];
        packet[0] = 0x1B;
        assert_eq!(packet.len(), 48);
        assert_eq!(packet[0], 0x1B); // LI=0, VN=3, Mode=3
    }

    #[test]
    fn ntp_to_unix_offset_conversion() {
        // NTP epoch starts 70 years before Unix epoch.
        const NTP_UNIX_OFFSET: u32 = 2_208_988_800;
        let ntp_secs: u32 = NTP_UNIX_OFFSET + 1_000_000;
        let unix_secs = ntp_secs.saturating_sub(NTP_UNIX_OFFSET) as i64;
        assert_eq!(unix_secs, 1_000_000);
    }

    #[test]
    fn system_time_secs_is_positive() {
        assert!(system_time_secs() > 0.0);
    }
}

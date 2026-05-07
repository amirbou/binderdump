// Parses the leading bytes of a binder transaction payload to extract the
// interface descriptor written by `IInterface::writeInterfaceToken` (AIDL
// libbinder side) and the analogous `IBase::writeInterfaceToken` for HIDL.

// Layout produced by libbinder Parcel::writeInterfaceToken
// (frameworks/native/libs/binder/Parcel.cpp). Order:
//   u32 strict_mode_policy
//   u32 work_source_uid           (API 29+, IPCThreadState::TF_CLEAR_BUF era)
//   u32 header marker 'SYS\0'     (API 30+, kHeader from IPCThreadState.h)
//   String16 interface_descriptor
pub fn parse_aidl_token(bytes: &[u8], android_sdk: u32) -> Option<String> {
    let mut off = 0usize;
    let _ = read_u32_le(bytes, off)?;
    off += 4;
    // work_source_uid: introduced for binder work-source tracking in API 29 (Android 10).
    if android_sdk >= 29 {
        let _ = read_u32_le(bytes, off)?;
        off += 4;
    }
    // RPC header marker: added in API 30 (Android 11) so the kernel can tell apart
    // a kBinder vs kHeader prefixed parcel; libbinder writes it unconditionally
    // from then on.
    if android_sdk >= 30 {
        let _ = read_u32_le(bytes, off)?;
        off += 4;
    }
    // String16: int32 char_count, then chars (u16 LE), then null term, padded to 4
    let char_count = read_i32_le(bytes, off)?;
    off += 4;
    if char_count < 0 {
        return Some(String::new()); // libbinder writes -1 for null/empty descriptors
    }
    let n = char_count as usize;
    let needed = n.checked_mul(2)?;
    let chars_slice = bytes.get(off..off + needed)?;
    let mut units: Vec<u16> = Vec::with_capacity(n);
    for chunk in chars_slice.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&units).ok()
}

pub fn parse_hidl_token(bytes: &[u8]) -> Option<String> {
    let len = read_i32_le(bytes, 0)?;
    if len < 0 {
        return None;
    }
    let n = len as usize;
    let s = bytes.get(4..4 + n)?;
    std::str::from_utf8(s).ok().map(|s| s.to_string())
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}
fn read_i32_le(buf: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_aidl_token(sdk: u32, descriptor: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // strict_mode_policy
        if sdk >= 29 {
            v.extend_from_slice(&0u32.to_le_bytes());
        } // work_source_uid
        if sdk >= 30 {
            // header marker 'SYS\0' = 0x53595300 in BE; libbinder writes it as a 4-byte int
            // (the exact byte order is host-endian when the int is written via writeInt32).
            v.extend_from_slice(&0x53595300u32.to_le_bytes());
        }
        let utf16: Vec<u16> = descriptor.encode_utf16().collect();
        v.extend_from_slice(&(utf16.len() as i32).to_le_bytes()); // char_count
        for u in &utf16 {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v.extend_from_slice(&[0, 0]); // null terminator
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn aidl_sdk30_basic() {
        let buf = build_aidl_token(30, "android.os.IServiceManager");
        assert_eq!(
            parse_aidl_token(&buf, 30),
            Some("android.os.IServiceManager".into())
        );
    }

    #[test]
    fn aidl_sdk28_no_worksource_no_marker() {
        let buf = build_aidl_token(28, "android.os.IFoo");
        assert_eq!(parse_aidl_token(&buf, 28), Some("android.os.IFoo".into()));
    }

    #[test]
    fn aidl_sdk29_worksource_no_marker() {
        let buf = build_aidl_token(29, "x.IBar");
        assert_eq!(parse_aidl_token(&buf, 29), Some("x.IBar".into()));
    }

    #[test]
    fn aidl_truncated_returns_none() {
        let buf = vec![0u8; 3];
        assert!(parse_aidl_token(&buf, 30).is_none());
    }

    #[test]
    fn aidl_empty_descriptor() {
        let buf = build_aidl_token(30, "");
        // Empty token is unusual but should not panic.
        assert_eq!(parse_aidl_token(&buf, 30), Some(String::new()));
    }

    fn build_hidl_token(descriptor: &str) -> Vec<u8> {
        let mut v = Vec::new();
        let bytes = descriptor.as_bytes();
        v.extend_from_slice(&(bytes.len() as i32).to_le_bytes()); // byte_count (excluding null)
        v.extend_from_slice(bytes);
        v.push(0); // null
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn hidl_basic() {
        let buf = build_hidl_token("android.hardware.audio@7.0::IDevice");
        assert_eq!(
            parse_hidl_token(&buf),
            Some("android.hardware.audio@7.0::IDevice".into())
        );
    }

    #[test]
    fn hidl_truncated_returns_none() {
        assert!(parse_hidl_token(&[0u8; 2]).is_none());
    }
}

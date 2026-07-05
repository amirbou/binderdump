// Parses the leading bytes of a binder transaction payload to extract the
// interface descriptor written by `IInterface::writeInterfaceToken` (AIDL
// libbinder side) and the analogous `IBase::writeInterfaceToken` for HIDL.

// Layout produced by libbinder Parcel::writeInterfaceToken
// (frameworks/native/libs/binder/Parcel.cpp). Order:
//   u32 strict_mode_policy
//   u32 work_source_uid           (API 29+, IPCThreadState::TF_CLEAR_BUF era)
//   u32 header marker 'SYS\0'     (API 30+, kHeader from IPCThreadState.h)
//   String16 interface_descriptor

// length of the writeInterfaceToken header before the String16 descriptor.
// policy(4) is always present; work_source_uid added in API 29 (Android 10);
// the RPC header marker added in API 30 (Android 11). See parse_aidl_token.
fn aidl_header_len(android_sdk: u32) -> usize {
    let work_source_uid = if android_sdk >= 29 { 4 } else { 0 };
    let header_marker = if android_sdk >= 30 { 4 } else { 0 };
    4 + work_source_uid + header_marker
}

// round up to the next 4-byte boundary. parcel writes are 4-aligned.
pub(crate) fn pad_to_4(n: usize) -> usize {
    (n + 3) & !3
}

// byte offset of the first parameter, i.e. just past the String16 interface
// descriptor written by writeInterfaceToken. None on a truncated token.
pub fn aidl_params_start(bytes: &[u8], android_sdk: u32) -> Option<usize> {
    let mut off = aidl_header_len(android_sdk);
    let char_count = read_i32_le(bytes, off)?;
    off += 4;
    if char_count < 0 {
        // null descriptor: libbinder wrote only the -1 int32.
        return Some(off);
    }
    let n = char_count as usize;
    // char_count UTF-16 units + a u16 NUL terminator, padded to 4 bytes.
    let body = n.checked_mul(2)?.checked_add(2)?;
    off = pad_to_4(off.checked_add(body)?);
    (off <= bytes.len()).then_some(off)
}

pub fn parse_aidl_token(bytes: &[u8], android_sdk: u32) -> Option<String> {
    // skip the writeInterfaceToken header (strict-mode policy, work_source_uid
    // for sdk>=29, RPC marker for sdk>=30). validate that those bytes exist.
    let hlen = aidl_header_len(android_sdk);
    if bytes.get(..hlen).is_none() {
        return None;
    }
    let mut off = hlen;
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

// byte offset of the first argument, i.e. just past the writeCString write
// emitted by libhwbinder's Parcel::writeInterfaceToken. writeCString writes
// the null-terminated string and pads the whole write to 4 bytes (libhwbinder
// Parcel::write → writeInplace → pad_size(len)). args start right after
// that 4-byte boundary. None on a truncated or absent token.
pub fn hidl_params_start(bytes: &[u8]) -> Option<usize> {
    let nul_pos = bytes.iter().position(|&b| b == 0)?;
    if nul_pos == 0 {
        return None;
    }
    Some(pad_to_4(nul_pos + 1))
}

// libhwbinder's Parcel::writeInterfaceToken calls writeCString, which writes the
// null-terminated bytes 4-byte aligned. No length prefix on the wire.
pub fn parse_hidl_token(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end])
        .ok()
        .map(|s| s.to_string())
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
        v.extend_from_slice(descriptor.as_bytes());
        v.push(0);
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

    // Real bytes captured from a SurfaceFlinger -> composer HAL transaction
    // on /dev/hwbinder. Wire format has no length prefix.
    #[test]
    fn hidl_real_capture_bytes() {
        let bytes: &[u8] = b"android.hardware.graphics.composer@2.1::IComposerClient\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00";
        assert_eq!(
            parse_hidl_token(bytes),
            Some("android.hardware.graphics.composer@2.1::IComposerClient".into())
        );
    }

    #[test]
    fn hidl_no_null_returns_none() {
        let bytes = b"android.hardware.audio@7.0::IDevice";
        assert!(parse_hidl_token(bytes).is_none());
    }

    #[test]
    fn hidl_params_start_after_token() {
        // "android.hardware.audio@7.0::IDevice" = 35 bytes + NUL = 36, pad_to_4(36) = 36
        let buf = build_hidl_token("android.hardware.audio@7.0::IDevice");
        let start = hidl_params_start(&buf).unwrap();
        assert_eq!(start, 36);
    }

    #[test]
    fn hidl_params_start_pads_to_4() {
        // token len 57 + NUL = 58, pad_to_4(58) = 60
        // "android.hardware.graphics.composer@2.4::IComposerCallback" = 57 chars
        let buf = build_hidl_token("android.hardware.graphics.composer@2.4::IComposerCallback");
        let start = hidl_params_start(&buf).unwrap();
        assert_eq!(start, 60, "57-char token + NUL = 58 bytes → padded to 60");
    }

    #[test]
    fn hidl_params_start_truncated_is_none() {
        assert!(hidl_params_start(&[0u8; 2]).is_none());
    }

    #[test]
    fn params_start_sdk30() {
        let buf = build_aidl_token(30, "android.os.IServiceManager");
        // header: policy(4)+worksource(4)+marker(4)=12; +char_count(4);
        // "android.os.IServiceManager" = 26 chars -> 26*2 + 2 (NUL) = 54, pad to 56
        assert_eq!(aidl_params_start(&buf, 30), Some(12 + 4 + 56));
    }

    #[test]
    fn params_start_sdk28_padded() {
        // "x.IFoo" = 6 chars -> 6*2 + 2 = 14, pad to 16
        let buf = build_aidl_token(28, "x.IFoo");
        assert_eq!(aidl_params_start(&buf, 28), Some(4 + 4 + 16));
    }

    #[test]
    fn params_start_empty_descriptor() {
        let buf = build_aidl_token(30, "");
        // char_count 0 -> 0 units + 2 NUL = 2, pad to 4
        assert_eq!(aidl_params_start(&buf, 30), Some(12 + 4 + 4));
    }

    #[test]
    fn params_start_truncated() {
        assert!(aidl_params_start(&[0u8; 5], 30).is_none());
    }

    #[test]
    fn params_start_null_descriptor() {
        // char_count == -1: libbinder writes only the int32, no chars/NUL/pad
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // policy
        buf.extend_from_slice(&0u32.to_le_bytes()); // worksource (sdk>=29)
        buf.extend_from_slice(&0x53595300u32.to_le_bytes()); // marker (sdk>=30)
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // char_count
        assert_eq!(aidl_params_start(&buf, 30), Some(12 + 4));
    }
}

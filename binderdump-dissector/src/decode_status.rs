// Builds the per-frame decode-status reason (why a transaction was not, or not fully,
// decoded). build_status is pure and unit-testable; register/emit hold the epan FFI side.

use crate::header_fields_manager::HeaderFieldsManager;
use binderdump_epan_sys::epan;
use binderdump_structs::event_layer::EventProtocol;
use std::ffi::{c_int, CString};

static mut EI_DECODE_INCOMPLETE: epan::expert_field = epan::expert_field { ei: -1, hf: -1 };
static mut EI_DECODE_NA: epan::expert_field = epan::expert_field { ei: -1, hf: -1 };

#[allow(static_mut_refs)]
pub fn register(proto_id: c_int) {
    unsafe {
        static mut EI: [epan::ei_register_info; 2] = unsafe { std::mem::zeroed() };
        EI[0] = epan::ei_register_info {
            ids: &raw mut EI_DECODE_INCOMPLETE,
            eiinfo: epan::expert_field_info {
                name: c"binderdump.decode_status.incomplete".as_ptr(),
                group: epan::PI_UNDECODED as c_int,
                severity: epan::PI_WARN as c_int,
                summary: c"Transaction not fully decoded".as_ptr(),
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: std::mem::zeroed(),
            },
        };
        EI[1] = epan::ei_register_info {
            ids: &raw mut EI_DECODE_NA,
            eiinfo: epan::expert_field_info {
                name: c"binderdump.decode_status.not_applicable".as_ptr(),
                group: epan::PI_UNDECODED as c_int,
                severity: epan::PI_NOTE as c_int,
                summary: c"Transaction payload not decoded".as_ptr(),
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: std::mem::zeroed(),
            },
        };
        let em = epan::expert_register_protocol(proto_id);
        epan::expert_register_field_array(em, EI.as_mut_ptr(), EI.len() as c_int);
    }
}

pub enum Severity {
    Incomplete,    // a gap we'd want closed (opaque param, corpus gap, partial) -> PI_WARN
    NotApplicable, // not expected to decode (no token, HIDL, uncorrelated reply) -> PI_NOTE
}

pub struct Status {
    pub text: String,
    pub severity: Severity,
}

pub struct StatusInput<'a> {
    pub method_source: &'a str,
    pub is_hwbinder: bool,
    pub interface: Option<&'a str>,
    pub method_name: Option<&'a str>,
    pub sdk: u32,
    pub code: u32,
    pub is_reply: bool,
    pub reply_correlated: bool,
    pub reply_method_known: bool,
    pub decoded_params: usize,
    pub raw_tail_reason: Option<&'a str>,
    pub undecoded_bytes: usize,
    // bytes trailing past the last cleanly-decoded param/return (0 when a RawTail
    // stopped decoding). >3 (beyond 4-byte parcel padding) signals the wire carried
    // more than the corpus signature models — i.e. a device newer than the corpus.
    pub trailing_bytes: usize,
    // set when a HIDL method was resolved but the HIDL decoder returned only a
    // top-level RawTail (e.g. the param type is not yet supported).
    pub payload_decoder_missing: bool,
}

fn incomplete(text: String) -> Option<Status> {
    Some(Status {
        text,
        severity: Severity::Incomplete,
    })
}
fn not_applicable(text: String) -> Option<Status> {
    Some(Status {
        text,
        severity: Severity::NotApplicable,
    })
}

pub fn build_status(i: &StatusInput) -> Option<Status> {
    // special codes are not payload frames; stay silent.
    if i.method_source == "special" {
        return None;
    }

    let iface = i.interface.unwrap_or("<unknown>");
    let method = i.method_name.unwrap_or("<unknown>");

    // reply frames: correlation-driven reasons.
    if i.is_reply {
        if !i.reply_correlated {
            return not_applicable("reply not correlated to a request".to_string());
        }
        if !i.reply_method_known {
            return incomplete("reply: originating method unknown".to_string());
        }
        if let Some(r) = i.raw_tail_reason {
            let bytes = if i.undecoded_bytes > 0 {
                format!("; {} bytes undecoded", i.undecoded_bytes)
            } else {
                String::new()
            };
            return incomplete(format!("reply: decode stopped at {}{}", r, bytes));
        }
        if i.decoded_params > 0
            && i.trailing_bytes > 3
            && !i.is_hwbinder
            && i.method_source != "native"
        {
            return incomplete(format!(
                "reply: {} unmodeled trailing bytes after the return value (a newer signature than the corpus, or an unconsumed object; corpus sdk {})",
                i.trailing_bytes, i.sdk
            ));
        }
        return None; // reply fully decoded
    }

    // requests: resolution-driven reasons.
    if i.payload_decoder_missing {
        let m = i.method_name.unwrap_or("<unknown>");
        return incomplete(format!("HIDL method {}: payload decode not implemented", m));
    }
    match i.method_source {
        "no_token" => {
            return not_applicable(
                "no interface token — not an AIDL/native transaction".to_string(),
            )
        }
        "unknown_iface" | "native" if i.method_name.is_none() => {
            return incomplete(format!("interface {} not in corpus (sdk {})", iface, i.sdk));
        }
        "unknown_code" => {
            return incomplete(format!("code {} not a known method of {}", i.code, iface));
        }
        _ => {}
    }

    // resolved method: partial or opaque.
    if let Some(r) = i.raw_tail_reason {
        let bytes = if i.undecoded_bytes > 0 {
            format!("; {} bytes undecoded", i.undecoded_bytes)
        } else {
            String::new()
        };
        return incomplete(format!(
            "method {}: decode stopped at {}{}",
            method, r, bytes
        ));
    }
    if i.decoded_params == 0 && i.undecoded_bytes > 0 {
        return incomplete(format!(
            "method {}: parameters not modeled (opaque); {} bytes undecoded",
            method, i.undecoded_bytes
        ));
    }
    // all params decoded but bytes remain past the last one — for a real AIDL method
    // that usually means the device runs a newer build than the base-release corpus
    // (an appended or grown parameter). Gated to AIDL: HIDL (hwbinder) trails its
    // scatter-gather buffer region, and native synthetic stubs are deliberately
    // incomplete, so trailing there is expected, not a version signal.
    if i.decoded_params > 0 && i.trailing_bytes > 3 && !i.is_hwbinder && i.method_source != "native"
    {
        return incomplete(format!(
            "method {}: {} unmodeled trailing bytes after all params (a newer signature than the corpus, or an unconsumed object; corpus sdk {})",
            method, i.trailing_bytes, i.sdk
        ));
    }
    None
}

pub fn emit(
    manager: &HeaderFieldsManager<EventProtocol>,
    tree: *mut epan::proto_node,
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    off: c_int,
    len: c_int,
    status: &Status,
) -> anyhow::Result<()> {
    let hf = manager
        .get_handle("binderdump.decode_status")
        .ok_or_else(|| anyhow::anyhow!("decode_status hf not registered"))?;
    // status.text with an interior NUL -> fall back to a literal that has none, so
    // the inner unwrap can't fail.
    let text = CString::new(status.text.as_str())
        .unwrap_or_else(|_| CString::new("decode status").unwrap());
    unsafe {
        let item = epan::proto_tree_add_string(tree, hf, tvb, off, len, text.as_ptr());
        epan::binderdump_proto_item_set_generated(item);
        let ei = match status.severity {
            Severity::Incomplete => &raw mut EI_DECODE_INCOMPLETE,
            Severity::NotApplicable => &raw mut EI_DECODE_NA,
        };
        epan::expert_add_info(pinfo, item, ei);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> StatusInput<'static> {
        StatusInput {
            method_source: "aosp",
            is_hwbinder: false,
            interface: Some("android.foo.IBar"),
            method_name: Some("doThing"),
            sdk: 35,
            code: 3,
            is_reply: false,
            reply_correlated: true,
            reply_method_known: true,
            decoded_params: 2,
            raw_tail_reason: None,
            undecoded_bytes: 0,
            trailing_bytes: 0,
            payload_decoder_missing: false,
        }
    }

    #[test]
    fn fully_decoded_is_none() {
        assert!(build_status(&base()).is_none());
    }

    #[test]
    fn no_token_is_not_applicable() {
        let mut i = base();
        i.method_source = "no_token";
        i.interface = None;
        i.method_name = None;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::NotApplicable));
        assert!(s.text.contains("no interface token"));
    }

    // hwbinder frames now follow the normal taxonomy. a hwbinder frame whose
    // token is absent still produces NotApplicable via the no_token arm.
    #[test]
    fn hwbinder_no_token_is_not_applicable() {
        let mut i = base();
        i.is_hwbinder = true;
        i.method_source = "no_token";
        i.interface = None;
        i.method_name = None;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::NotApplicable));
        assert!(s.text.contains("no interface token"));
    }

    #[test]
    fn hidl_decoder_missing_is_incomplete() {
        let mut i = base();
        i.is_hwbinder = true;
        i.method_name = Some("executeCommands");
        i.payload_decoder_missing = true;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::Incomplete));
        assert!(
            s.text.contains("executeCommands") && s.text.contains("payload decode not implemented")
        );
    }

    #[test]
    fn unknown_iface_is_incomplete_and_names_iface() {
        let mut i = base();
        i.method_source = "unknown_iface";
        i.method_name = None;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::Incomplete));
        assert!(s.text.contains("android.foo.IBar") && s.text.contains("not in corpus"));
    }

    #[test]
    fn unknown_code_is_incomplete() {
        let mut i = base();
        i.method_source = "unknown_code";
        i.method_name = None;
        let s = build_status(&i).unwrap();
        assert!(s.text.contains("code 3") && s.text.contains("android.foo.IBar"));
    }

    #[test]
    fn resolved_stub_with_leftover_is_opaque() {
        let mut i = base();
        i.decoded_params = 0;
        i.undecoded_bytes = 40;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::Incomplete));
        assert!(
            s.text.contains("doThing")
                && s.text.contains("not modeled")
                && s.text.contains("40 bytes")
        );
    }

    #[test]
    fn resolved_zero_params_no_leftover_is_none() {
        let mut i = base();
        i.decoded_params = 0;
        i.undecoded_bytes = 0;
        assert!(build_status(&i).is_none()); // genuine void method
    }

    #[test]
    fn trailing_after_full_decode_flags_newer_device() {
        let mut i = base();
        i.decoded_params = 2;
        i.trailing_bytes = 8; // an appended parameter the corpus doesn't model
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::Incomplete));
        assert!(
            s.text.contains("trailing bytes") && s.text.contains("newer signature than the corpus")
        );
    }

    #[test]
    fn trailing_within_padding_is_none() {
        let mut i = base();
        i.decoded_params = 2;
        i.trailing_bytes = 3; // 4-byte parcel alignment padding, not a real tail
        assert!(build_status(&i).is_none());
    }

    #[test]
    fn reply_trailing_after_return_flags_newer_device() {
        let mut i = base();
        i.is_reply = true;
        i.decoded_params = 1;
        i.trailing_bytes = 8;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::Incomplete));
        assert!(s.text.contains("reply:") && s.text.contains("newer signature than the corpus"));
    }

    #[test]
    fn native_reply_trailing_not_flagged() {
        // native synthetic stubs are deliberately incomplete; their trailing bytes
        // are expected, not a version signal — same exclusion as the request path.
        let mut i = base();
        i.is_reply = true;
        i.method_source = "native";
        i.decoded_params = 1;
        i.trailing_bytes = 8;
        assert!(build_status(&i).is_none());
    }

    #[test]
    fn hwbinder_trailing_not_flagged() {
        // HIDL replies trail their scatter-gather buffer region.
        let mut i = base();
        i.is_reply = true;
        i.is_hwbinder = true;
        i.decoded_params = 1;
        i.trailing_bytes = 40;
        assert!(build_status(&i).is_none());
    }

    #[test]
    fn raw_tail_names_the_stop_reason() {
        let mut i = base();
        i.raw_tail_reason =
            Some("param cmds (undecodable type UserDefined(\"InputWindowCommands\"))");
        i.undecoded_bytes = 24;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::Incomplete));
        assert!(
            s.text.contains("decode stopped at")
                && s.text.contains("InputWindowCommands")
                && s.text.contains("24 bytes")
        );
    }

    #[test]
    fn raw_tail_zero_undecoded_omits_byte_count() {
        let mut i = base();
        i.raw_tail_reason = Some("buffer overrun");
        i.undecoded_bytes = 0;
        let s = build_status(&i).unwrap();
        assert!(s.text.contains("decode stopped at"));
        assert!(!s.text.contains("bytes undecoded"));
    }

    #[test]
    fn reply_uncorrelated_is_not_applicable() {
        let mut i = base();
        i.is_reply = true;
        i.reply_correlated = false;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::NotApplicable));
        assert!(s.text.contains("not correlated"));
    }

    #[test]
    fn reply_method_unknown_is_incomplete() {
        let mut i = base();
        i.is_reply = true;
        i.reply_correlated = true;
        i.reply_method_known = false;
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::Incomplete));
        assert!(s.text.contains("originating method unknown"));
    }

    #[test]
    fn special_code_is_none() {
        let mut i = base();
        i.method_source = "special";
        assert!(build_status(&i).is_none());
    }
}

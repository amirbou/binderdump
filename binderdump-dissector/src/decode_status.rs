// Builds the per-frame decode-status reason (why a transaction was not, or not
// fully, decoded) from resolve/decode state. Pure — no Wireshark types here so
// it is unit-testable; registration and emit live in the sibling fns below.

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
            return incomplete(format!(
                "reply: decode stopped at {}; {} bytes undecoded",
                r, i.undecoded_bytes
            ));
        }
        return None; // reply fully decoded
    }

    // requests: resolution-driven reasons.
    if i.is_hwbinder {
        return not_applicable("HIDL/hwbinder interface — not decoded".to_string());
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
        return incomplete(format!(
            "method {}: decode stopped at {}; {} bytes undecoded",
            method, r, i.undecoded_bytes
        ));
    }
    if i.decoded_params == 0 && i.undecoded_bytes > 0 {
        return incomplete(format!(
            "method {}: parameters not modeled (opaque); {} bytes undecoded",
            method, i.undecoded_bytes
        ));
    }
    None
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

    #[test]
    fn hwbinder_is_not_applicable() {
        let mut i = base();
        i.is_hwbinder = true;
        i.method_source = "no_token";
        let s = build_status(&i).unwrap();
        assert!(matches!(s.severity, Severity::NotApplicable));
        assert!(s.text.contains("HIDL"));
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

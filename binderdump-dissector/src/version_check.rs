// Reads the captured binderdump version from the IDB IfDescription string
// (`binderdump-version=X.Y.Z`) and reports whether it matches the dissector's
// compile-time version.

pub const DISSECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

const PREFIX: &str = "binderdump-version=";

pub fn captured_version_from_idb_description(descr: &str) -> Option<&str> {
    descr.strip_prefix(PREFIX)
}

pub fn is_mismatch(captured: &str) -> bool {
    // Within one major version the pcapng wire format is stable (wire structs
    // are append-only, per SemVer from 1.0.0 on), so a capture is incompatible
    // only when its major version differs from the dissector's. An unparseable
    // version is treated as incompatible.
    match (major(captured), major(DISSECTOR_VERSION)) {
        (Some(c), Some(d)) => c != d,
        _ => true,
    }
}

fn major(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_version_from_descr() {
        assert_eq!(
            captured_version_from_idb_description("binderdump-version=1.2.3"),
            Some("1.2.3")
        );
    }

    #[test]
    fn rejects_unprefixed_descr() {
        assert!(captured_version_from_idb_description("/dev/binder").is_none());
    }

    #[test]
    fn no_mismatch_when_versions_match() {
        assert!(!is_mismatch(DISSECTOR_VERSION));
    }

    #[test]
    fn same_major_different_minor_is_not_mismatch() {
        let m = DISSECTOR_VERSION.split('.').next().unwrap();
        assert!(!is_mismatch(&format!("{m}.99.99")));
    }

    #[test]
    fn different_major_is_mismatch() {
        let m: u32 = DISSECTOR_VERSION
            .split('.')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(is_mismatch(&format!("{}.0.0", m + 1)));
        assert!(is_mismatch("0.1.0"));
    }

    #[test]
    fn unparseable_version_is_mismatch() {
        assert!(is_mismatch("not-a-version"));
    }
}

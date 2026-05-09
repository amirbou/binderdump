// Reads the captured binderdump version from the IDB IfDescription string
// (`binderdump-version=X.Y.Z`) and reports whether it matches the dissector's
// compile-time version.

pub const DISSECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

const PREFIX: &str = "binderdump-version=";

pub fn captured_version_from_idb_description(descr: &str) -> Option<&str> {
    descr.strip_prefix(PREFIX)
}

pub fn is_mismatch(captured: &str) -> bool {
    captured != DISSECTOR_VERSION
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
    fn mismatch_when_versions_differ() {
        assert!(is_mismatch("0.0.0"));
    }

    #[test]
    fn no_mismatch_when_versions_match() {
        assert!(!is_mismatch(DISSECTOR_VERSION));
    }
}

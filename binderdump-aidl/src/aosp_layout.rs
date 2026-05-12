use std::path::{Path, PathBuf};

/// Resolve an AIDL fqn into a path relative to a corpus root.
/// Example: `android.os.IServiceManager` → `android-34/aidl/android/os/IServiceManager.aidl`.
pub fn aidl_path(root: &Path, sdk: u32, fqn: &str) -> PathBuf {
    let rel = fqn.replace('.', "/");
    root.join(format!("android-{}", sdk))
        .join("aidl")
        .join(rel + ".aidl")
}

/// Resolve a HIDL fqn into a path relative to a corpus root.
/// Example: `android.hardware.audio@4.0::IStream` →
///   `android-34/hal/android/hardware/audio/4.0/IStream.hal`.
/// Returns `None` if `fqn` doesn't have the `pkg@ver::Name` shape.
pub fn hidl_path(root: &Path, sdk: u32, fqn: &str) -> Option<PathBuf> {
    let (pkg_at_ver, name) = fqn.split_once("::")?;
    let (pkg, ver) = pkg_at_ver.split_once('@')?;
    let pkg_path = pkg.replace('.', "/");
    Some(
        root.join(format!("android-{}", sdk))
            .join("hal")
            .join(pkg_path)
            .join(ver)
            .join(format!("{}.hal", name)),
    )
}

/// Read the `package <name>;` declaration from a `.aidl` file's text and
/// return the package fqn (e.g. `"android.os"`). Returns `None` if no
/// package line is found within the first 64 lines (the limit guards
/// against pathological inputs).
pub fn aidl_package_from_source(src: &str) -> Option<String> {
    for line in src.lines().take(64) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("package ") {
            // take up to the first `;` or whitespace — handles both
            // `package a.b;` on its own line and `package a.b; interface …`
            let pkg = rest
                .split(|c: char| c == ';' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .trim();
            if !pkg.is_empty() {
                return Some(pkg.to_string());
            }
        }
    }
    None
}

/// Read the `package <name>@<ver>;` declaration from a `.hal` file's text
/// and return the versioned package (e.g. `"android.hardware.audio@4.0"`).
/// Returns `None` if no `package` line is found.
pub fn hidl_package_from_source(src: &str) -> Option<String> {
    for line in src.lines().take(64) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("package ") {
            let pkg = rest
                .split(|c: char| c == ';' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .trim();
            if !pkg.is_empty() && pkg.contains('@') {
                return Some(pkg.to_string());
            }
        }
    }
    None
}

/// Read all interface declarations in a `.aidl` source. Returns a list of
/// fully-qualified names (`<pkg>.<iface>`). Used by the lazy loader's
/// fqn→path index. Crucially this only does cheap text-level scanning;
/// the full chumsky parse runs only when the file is actually loaded for
/// resolution.
pub fn aidl_interfaces_in(src: &str) -> Vec<String> {
    let Some(pkg) = aidl_package_from_source(src) else {
        return Vec::new();
    };
    // scan for `interface <Name>` occurrences anywhere in the source —
    // real files have them on their own lines, but the text search also
    // handles compact single-line test fixtures correctly.
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(pos) = rest.find("interface ") {
        rest = &rest[pos + "interface ".len()..];
        // require that the match is at a word boundary (preceded by whitespace,
        // `;`, or start of string) to avoid false positives inside strings or
        // identifiers like `MyInterface `.
        let before = &src[..src.len() - rest.len() - "interface ".len()];
        if let Some(prev) = before.chars().last() {
            if prev.is_alphanumeric() || prev == '_' {
                continue;
            }
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.push(format!("{}.{}", pkg, name));
        }
    }
    out
}

/// Same shape, HIDL flavor. Returns `<pkg>@<ver>::<iface>` strings.
pub fn hidl_interfaces_in(src: &str) -> Vec<String> {
    let Some(pkg) = hidl_package_from_source(src) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(pos) = rest.find("interface ") {
        rest = &rest[pos + "interface ".len()..];
        let before = &src[..src.len() - rest.len() - "interface ".len()];
        if let Some(prev) = before.chars().last() {
            if prev.is_alphanumeric() || prev == '_' {
                continue;
            }
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.push(format!("{}::{}", pkg, name));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn aidl_path_dotted() {
        let p = aidl_path(Path::new("data/aosp"), 34, "android.os.IServiceManager");
        assert_eq!(
            p,
            PathBuf::from("data/aosp/android-34/aidl/android/os/IServiceManager.aidl")
        );
    }

    #[test]
    fn aidl_path_single_segment() {
        let p = aidl_path(Path::new("/x"), 36, "ICustom");
        assert_eq!(p, PathBuf::from("/x/android-36/aidl/ICustom.aidl"));
    }

    #[test]
    fn hidl_path_versioned() {
        let p = hidl_path(
            Path::new("data/aosp"),
            34,
            "android.hardware.audio@4.0::IStream",
        )
        .expect("valid hidl fqn");
        assert_eq!(
            p,
            PathBuf::from("data/aosp/android-34/hal/android/hardware/audio/4.0/IStream.hal")
        );
    }

    #[test]
    fn hidl_path_invalid_fqn_returns_none() {
        assert!(hidl_path(Path::new("/x"), 34, "android.os.IFoo").is_none());
    }

    #[test]
    fn aidl_package_basic() {
        assert_eq!(
            aidl_package_from_source("package a.b.c; interface IFoo {}"),
            Some("a.b.c".to_string())
        );
    }

    #[test]
    fn aidl_package_with_leading_comments() {
        let src = "// a comment\n/* block */\npackage com.example; interface IFoo {}";
        assert_eq!(
            aidl_package_from_source(src),
            Some("com.example".to_string())
        );
    }

    #[test]
    fn aidl_interfaces_extracts_all() {
        let src = "package a.b; interface IFoo { void m(); } interface IBar { }";
        let v = aidl_interfaces_in(src);
        assert_eq!(v, vec!["a.b.IFoo", "a.b.IBar"]);
    }

    #[test]
    fn aidl_interfaces_no_package_returns_empty() {
        assert!(aidl_interfaces_in("interface IFoo {}").is_empty());
    }

    #[test]
    fn hidl_package_versioned() {
        assert_eq!(
            hidl_package_from_source("package a.b@1.0; interface IFoo {}"),
            Some("a.b@1.0".to_string())
        );
    }

    #[test]
    fn hidl_interfaces_extracts_versioned() {
        let src = "package a.b@1.0; interface IFoo { f(); }";
        assert_eq!(hidl_interfaces_in(src), vec!["a.b@1.0::IFoo"]);
    }
}

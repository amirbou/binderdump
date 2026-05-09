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
}

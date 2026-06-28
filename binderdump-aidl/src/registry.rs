// Layered (interface, code) -> Method lookup. Three sources stack, last
// wins: runtime .aidl/.hal overlays from the user's pref dir; the bundled
// AOSP corpus loaded lazily on demand from Registry::with_aosp_dir(); and
// special transaction codes hard-coded in this file.

// Special transaction codes from frameworks/native/libs/binder/include/binder/IBinder.h.
// Each is `B_PACK_CHARS('_','X','Y','Z')` which packs ASCII into u32:
//   PING_TRANSACTION          = '_PNG'
//   DUMP_TRANSACTION          = '_DMP'
//   SHELL_COMMAND_TRANSACTION = '_CMD'
//   INTERFACE_TRANSACTION     = '_NTF'
//   SYSPROPS_TRANSACTION      = '_SPR'
//   EXTENSION_TRANSACTION     = '_EXT'
//   TWEET_TRANSACTION         = '_TWT'
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialTxn {
    Ping,
    Dump,
    ShellCommand,
    Interface,
    Sysprops,
    Extension,
    Tweet,
}

pub fn lookup_special(code: u32) -> Option<SpecialTxn> {
    match code {
        0x5f504e47 => Some(SpecialTxn::Ping),
        0x5f444d50 => Some(SpecialTxn::Dump),
        0x5f434d44 => Some(SpecialTxn::ShellCommand),
        0x5f4e5446 => Some(SpecialTxn::Interface),
        0x5f535052 => Some(SpecialTxn::Sysprops),
        0x5f455854 => Some(SpecialTxn::Extension),
        0x5f545754 => Some(SpecialTxn::Tweet),
        _ => None,
    }
}

pub fn special_method_name(s: SpecialTxn) -> &'static str {
    match s {
        SpecialTxn::Ping => "PING_TRANSACTION",
        SpecialTxn::Dump => "DUMP_TRANSACTION",
        SpecialTxn::ShellCommand => "SHELL_COMMAND_TRANSACTION",
        SpecialTxn::Interface => "INTERFACE_TRANSACTION",
        SpecialTxn::Sysprops => "SYSPROPS_TRANSACTION",
        SpecialTxn::Extension => "EXTENSION_TRANSACTION",
        SpecialTxn::Tweet => "TWEET_TRANSACTION",
    }
}

// True if `name` is one of the special_method_name sentinels. Lets the reply
// path recognise an interface-agnostic transaction from the resolved name when
// the original transaction code isn't on hand.
pub fn is_special_method_name(name: &str) -> bool {
    const ALL: [SpecialTxn; 7] = [
        SpecialTxn::Ping,
        SpecialTxn::Dump,
        SpecialTxn::ShellCommand,
        SpecialTxn::Interface,
        SpecialTxn::Sysprops,
        SpecialTxn::Extension,
        SpecialTxn::Tweet,
    ];
    ALL.iter().any(|&s| special_method_name(s) == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_recognized() {
        assert_eq!(lookup_special(0x5f504e47), Some(SpecialTxn::Ping));
    }
    #[test]
    fn special_method_names_round_trip() {
        assert!(is_special_method_name("PING_TRANSACTION"));
        assert!(is_special_method_name("INTERFACE_TRANSACTION"));
        assert!(!is_special_method_name("checkService"));
        assert!(!is_special_method_name(""));
    }
    #[test]
    fn dump_recognized() {
        assert_eq!(lookup_special(0x5f444d50), Some(SpecialTxn::Dump));
    }
    #[test]
    fn shell_recognized() {
        assert_eq!(lookup_special(0x5f434d44), Some(SpecialTxn::ShellCommand));
    }
    #[test]
    fn interface_recognized() {
        assert_eq!(lookup_special(0x5f4e5446), Some(SpecialTxn::Interface));
    }
    #[test]
    fn sysprops_recognized() {
        assert_eq!(lookup_special(0x5f535052), Some(SpecialTxn::Sysprops));
    }
    #[test]
    fn extension_recognized() {
        assert_eq!(lookup_special(0x5f455854), Some(SpecialTxn::Extension));
    }
    #[test]
    fn tweet_recognized() {
        assert_eq!(lookup_special(0x5f545754), Some(SpecialTxn::Tweet));
    }
    #[test]
    fn first_call_not_special() {
        assert!(lookup_special(1).is_none());
    }

    use crate::model::*;

    fn iface(fqn: &str, methods: &[&str]) -> Interface {
        Interface {
            fqn: fqn.to_string(),
            flavor: Flavor::Aidl,
            base_code: 1,
            methods: methods
                .iter()
                .map(|n| Method {
                    name: n.to_string(),
                    params: vec![],
                    return_type: None,
                    oneway: false,
                    code: None,
                })
                .collect(),
            extends: None,
        }
    }

    #[test]
    fn registry_overlay_hit() {
        let mut overlay = OverlayLayer {
            source_path: "/tmp/x.aidl".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
        };
        overlay
            .interfaces
            .insert("a.b.IFoo".into(), iface("a.b.IFoo", &["start", "stop"]));
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        let l = reg.resolve(34, "a.b.IFoo", 1);
        match l {
            Lookup::Hit { method, source } => {
                assert_eq!(method.name, "start");
                assert!(matches!(source, Source::Overlay(_)));
            }
            _ => panic!("expected Hit"),
        }
    }

    #[test]
    fn registry_special_takes_precedence_over_overlay() {
        let mut overlay = OverlayLayer {
            source_path: "/tmp/x.aidl".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
        };
        // Even if an overlay declared a method at PING's value, special table wins.
        overlay
            .interfaces
            .insert("a.b.IFoo".into(), iface("a.b.IFoo", &[]));
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        match reg.resolve(34, "a.b.IFoo", 0x5f504e47) {
            Lookup::SpecialCode(SpecialTxn::Ping) => {}
            other => panic!("expected SpecialCode(Ping), got {:?}", other),
        }
    }

    #[test]
    fn registry_unknown_interface() {
        let reg = Registry::empty();
        assert!(matches!(
            reg.resolve(34, "missing.IGhost", 1),
            Lookup::UnknownInterface
        ));
    }

    #[test]
    fn registry_unknown_code() {
        let mut overlay = OverlayLayer {
            source_path: "/tmp/x.aidl".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
        };
        overlay
            .interfaces
            .insert("a.b.IFoo".into(), iface("a.b.IFoo", &["only"]));
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        assert!(matches!(
            reg.resolve(34, "a.b.IFoo", 99),
            Lookup::UnknownCode { .. }
        ));
    }

    // hand-rolled instead of using `tempfile`: pulling tempfile transitively
    // breaks on the rustix + linux-raw-sys + nightly rustc combo this workspace
    // currently uses for the cross-compiled targets.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "binderdump-aidl-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst),
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_overlays_parses_aidl_files() {
        let tmp = TempDir::new();
        std::fs::write(
            tmp.path().join("vendor.aidl"),
            "package x.y; interface IZap { void custom(); }",
        )
        .unwrap();
        let overlays = Registry::load_overlay_dir(tmp.path()).unwrap();
        assert_eq!(overlays.len(), 1);
        assert!(overlays[0].interfaces.contains_key("x.y.IZap"));
    }

    #[test]
    fn load_overlays_skips_unparseable_and_keeps_others() {
        let tmp = TempDir::new();
        std::fs::write(
            tmp.path().join("good.aidl"),
            "package g; interface IGood { void f(); }",
        )
        .unwrap();
        std::fs::write(tmp.path().join("bad.aidl"), "this is not aidl @@@@").unwrap();
        let overlays = Registry::load_overlay_dir(tmp.path()).unwrap();
        // The good file should always load. The bad file may or may not produce
        // an empty layer depending on parser leniency; assert at least the good one.
        assert!(overlays
            .iter()
            .any(|l| l.interfaces.contains_key("g.IGood")));
    }

    #[test]
    fn lazy_resolve_loads_aidl_on_demand() {
        let tmp = TempDir::new();
        let aidl_dir = tmp.path().join("android-34/aidl/com/example");
        std::fs::create_dir_all(&aidl_dir).unwrap();
        std::fs::write(
            aidl_dir.join("IFoo.aidl"),
            "package com.example; interface IFoo { void hello(); void world(); }",
        )
        .unwrap();

        let reg = Registry::with_aosp_dir(tmp.path().to_path_buf());

        match reg.resolve(34, "com.example.IFoo", 1) {
            Lookup::Hit { method, source } => {
                assert!(matches!(source, Source::Lazy));
                assert_eq!(method.name, "hello");
            }
            other => panic!("expected Hit, got {:?}", other),
        }

        // second call: cached, same outcome
        match reg.resolve(34, "com.example.IFoo", 2) {
            Lookup::Hit { method, .. } => assert_eq!(method.name, "world"),
            other => panic!("expected Hit, got {:?}", other),
        }
    }

    #[test]
    fn lazy_resolve_misses_unknown_fqn_caches_negative() {
        let tmp = TempDir::new();
        std::fs::create_dir_all(tmp.path().join("android-34/aidl")).unwrap();

        let reg = Registry::with_aosp_dir(tmp.path().to_path_buf());

        let r1 = reg.resolve(34, "com.does.not.IExist", 1);
        assert!(matches!(r1, Lookup::UnknownInterface));
        let r2 = reg.resolve(34, "com.does.not.IExist", 1);
        assert!(matches!(r2, Lookup::UnknownInterface));
    }

    #[test]
    fn lazy_resolve_consults_index_for_misplaced_aidl() {
        // File at <root>/android-34/aidl/some/wrong/path/IFoo.aidl
        // declares `package com.example; interface IFoo`. Lookup by fqn
        // `com.example.IFoo` must succeed via the index, even though
        // aidl_path() wouldn't find it directly.
        let tmp = TempDir::new();
        let misplaced = tmp.path().join("android-34/aidl/wrong/place/here");
        std::fs::create_dir_all(&misplaced).unwrap();
        std::fs::write(
            misplaced.join("IFoo.aidl"),
            "package com.example; interface IFoo { void hello(); }",
        )
        .unwrap();

        let reg = Registry::with_aosp_dir(tmp.path().to_path_buf());
        match reg.resolve(34, "com.example.IFoo", 1) {
            Lookup::Hit { method, .. } => assert_eq!(method.name, "hello"),
            other => panic!("expected Hit, got {:?}", other),
        }
    }

    #[test]
    fn native_layer_resolves_after_aosp_miss() {
        use std::io::Write;
        let tmp = TempDir::new();
        let native_dir = tmp.path().join("native");
        std::fs::create_dir_all(native_dir.join("android-34/aidl/android/utils")).unwrap();
        let mut f =
            std::fs::File::create(native_dir.join("android-34/aidl/android/utils/IMemory.aidl"))
                .unwrap();
        writeln!(
            f,
            "package android.utils; interface IMemory {{ void getMemory() = 1; }}"
        )
        .unwrap();

        let reg = Registry::empty().with_native_dir(&native_dir);
        match reg.resolve(34, "android.utils.IMemory", 1) {
            Lookup::Hit { method, source } => {
                assert_eq!(method.name, "getMemory");
                assert!(matches!(source, Source::Native));
            }
            other => panic!("expected Native hit, got {:?}", other),
        }
    }

    #[test]
    fn bundled_native_corpus_resolves_gui_family() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);
        for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
            for (fqn, code, expected) in [
                // code 1 = ON_DISCONNECT (onFrameAvailable is code 2)
                ("android.gui.IConsumerListener", 1u32, "onDisconnect"),
                ("android.gui.IGraphicBufferConsumer", 1, "acquireBuffer"),
                (
                    "android.gui.ITransactionComposerListener",
                    1,
                    "onTransactionCompleted",
                ),
                ("android.gui.SensorEventConnection", 1, "getSensorChannel"),
                ("android.gui.SensorServer", 1, "getSensorList"),
            ] {
                match reg.resolve(sdk, fqn, code) {
                    Lookup::Hit { method, .. } => {
                        assert_eq!(method.name, expected, "sdk={sdk} fqn={fqn}")
                    }
                    other => panic!("expected hit for sdk={sdk} fqn={fqn}, got {:?}", other),
                }
            }
        }
    }

    #[test]
    fn bundled_native_corpus_resolves_imemory() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);
        for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
            match reg.resolve(sdk, "android.utils.IMemory", 1) {
                Lookup::Hit { method, source } => {
                    assert_eq!(method.name, "getMemory", "sdk={sdk}");
                    assert!(matches!(source, Source::Native));
                }
                other => panic!(
                    "expected Native hit for IMemory at sdk={sdk}, got {:?}",
                    other
                ),
            }
        }
    }

    #[test]
    fn bundled_native_corpus_resolves_media_family() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);
        // code-1 method names verified stable across android-33..37 from .aidl sources.
        for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
            for (fqn, code, expected) in [
                ("android.media.IDataSource", 1u32, "getIMemory"),
                ("android.media.IMediaCodecList", 1, "create"),
                ("android.media.IMediaExtractor", 1, "countTracks"),
                ("android.media.IMediaLogService", 1, "registerWriter"),
                ("android.media.IMediaMetadataRetriever", 1, "disconnect"),
                ("android.media.IMediaPlayer", 1, "disconnect"),
                ("android.media.IMediaPlayerClient", 1, "notify"),
                ("android.media.IMediaPlayerService", 1, "create"),
                ("android.media.IMediaRecorder", 1, "release"),
                ("android.media.IMediaRecorderClient", 1, "notify"),
                ("android.media.IMediaSource", 1, "start"),
                ("android.media.IRemoteDisplay", 1, "dispose"),
                (
                    "android.media.IRemoteDisplayClient",
                    1,
                    "onDisplayConnected",
                ),
            ] {
                match reg.resolve(sdk, fqn, code) {
                    Lookup::Hit { method, .. } => {
                        assert_eq!(method.name, expected, "sdk={sdk} fqn={fqn}");
                    }
                    other => panic!("expected hit for sdk={sdk} fqn={fqn}, got {:?}", other),
                }
            }
        }
    }

    #[test]
    fn bundled_native_corpus_resolves_hardware_family() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);
        for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
            for fqn in [
                "android.hardware.ICameraRecordingProxy",
                // ICameraRecordingProxyListener: deleted post-android-11; shipped to all
                // SDKs (like ISurfaceComposer) for vendor binary compat.
                "android.hardware.ICameraRecordingProxyListener",
                "android.hardware.IStreamSource",
            ] {
                assert!(
                    matches!(reg.resolve(sdk, fqn, 1), Lookup::Hit { .. }),
                    "no Hit at code 1 for sdk={sdk} fqn={fqn}",
                );
            }
            // IStreamListener codes start at 5 (shared enum with IStreamSource in same TU)
            assert!(
                matches!(
                    reg.resolve(sdk, "android.hardware.IStreamListener", 5),
                    Lookup::Hit { .. }
                ),
                "no Hit at code 5 for sdk={sdk} android.hardware.IStreamListener",
            );
            // IOMXObserver::onMessages is code 20 (shared enum with IOMXNode in IOMX.cpp)
            assert!(
                matches!(
                    reg.resolve(sdk, "android.hardware.IOMXObserver", 20),
                    Lookup::Hit { .. }
                ),
                "no Hit at code 20 for sdk={sdk} android.hardware.IOMXObserver",
            );
        }
    }

    #[test]
    fn bundled_native_corpus_resolves_drm_and_misc() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);
        for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
            assert!(
                matches!(
                    reg.resolve(sdk, "drm.IDrmServiceListener", 1),
                    Lookup::Hit { .. }
                ),
                "no Hit for sdk={sdk} drm.IDrmServiceListener",
            );
            assert!(
                matches!(
                    reg.resolve(sdk, "com.android.car.procfsinspector.IProcfsInspector", 1),
                    Lookup::Hit { .. }
                ),
                "no Hit for sdk={sdk} IProcfsInspector",
            );
            assert!(
                matches!(
                    reg.resolve(sdk, "android.graphicsenv.IGpuService", 1),
                    Lookup::Hit { .. }
                ),
                "no Hit for sdk={sdk} IGpuService",
            );
            // IDrmManagerService has 32 entries — assert at least 10
            let drm_count = (1..=50)
                .filter(|c| {
                    matches!(
                        reg.resolve(sdk, "drm.IDrmManagerService", *c),
                        Lookup::Hit { .. }
                    )
                })
                .count();
            assert!(
                drm_count >= 10,
                "sdk={sdk} IDrmManagerService only has {drm_count} method entries",
            );
        }
    }

    #[test]
    fn every_native_fqn_resolves_via_corpus() {
        // per-(sdk, fqn) exemptions. add with a brief reason when an interface
        // has no .aidl in data/native/ for that sdk level.
        const NO_SYNTHETIC_AIDL: &[(u32, &str)] = &[];

        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);

        for fqn in crate::native_interfaces::all() {
            for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
                if NO_SYNTHETIC_AIDL.contains(&(sdk, fqn)) {
                    continue;
                }
                // Probe a reasonable code range — 64 covers every interface in the
                // corpus (largest is ISurfaceComposer at 63 entries). Require at
                // least one Hit to prove the AIDL has callable methods, not just
                // an empty interface body.
                let has_hit = (1..=64u32)
                    .any(|code| matches!(reg.resolve(sdk, fqn, code), Lookup::Hit { .. }));
                assert!(
                    has_hit,
                    "FQN {fqn} at sdk={sdk}: no Lookup::Hit in code range 1..=64. \
                     Either the synthetic AIDL is missing methods, or the codes are out of range.",
                );
            }
        }
    }

    #[test]
    fn native_layer_does_not_shadow_aosp() {
        use std::io::Write;
        let tmp = TempDir::new();

        // AOSP-side fixture
        let aosp_dir = tmp.path().join("aosp");
        let pkg = aosp_dir.join("android-34/aidl/x/y");
        std::fs::create_dir_all(&pkg).unwrap();
        let mut f = std::fs::File::create(pkg.join("IShared.aidl")).unwrap();
        writeln!(
            f,
            "package x.y; interface IShared {{ void aosp_method() = 1; }}"
        )
        .unwrap();

        // Native-side fixture with the SAME fqn but different method
        let native_dir = tmp.path().join("native");
        std::fs::create_dir_all(native_dir.join("android-34/aidl/x/y")).unwrap();
        let mut g =
            std::fs::File::create(native_dir.join("android-34/aidl/x/y/IShared.aidl")).unwrap();
        writeln!(
            g,
            "package x.y; interface IShared {{ void native_method() = 1; }}"
        )
        .unwrap();

        let reg = Registry::with_aosp_dir(aosp_dir).with_native_dir(&native_dir);
        match reg.resolve(34, "x.y.IShared", 1) {
            Lookup::Hit { method, source } => {
                assert_eq!(method.name, "aosp_method");
                assert!(matches!(source, Source::Lazy));
            }
            other => panic!("expected AOSP Lazy hit, got {:?}", other),
        }
    }

    #[test]
    fn parcelable_def_loads_from_overlay() {
        use crate::model::{Field, Parcelable, Prim, TypeRef};
        let mut overlay = OverlayLayer {
            source_path: "x".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
        };
        overlay.parcelables.insert(
            "a.b.P".into(),
            Parcelable {
                fqn: "a.b.P".into(),
                fields: vec![Field {
                    name: "id".into(),
                    ty: TypeRef::Primitive(Prim::I32),
                }],
            },
        );
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        let p = reg.parcelable_def(34, "a.b.P").expect("overlay parcelable");
        assert_eq!(p.fields.len(), 1);
        assert!(reg.parcelable_def(34, "a.b.Missing").is_none());
    }

    #[test]
    fn union_def_loads_from_overlay() {
        use crate::model::{Field, Prim, TypeRef, Union};
        let mut overlay = OverlayLayer {
            source_path: "x".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
        };
        overlay.unions.insert(
            "a.b.U".into(),
            Union {
                fqn: "a.b.U".into(),
                fields: vec![Field {
                    name: "n".into(),
                    ty: TypeRef::Primitive(Prim::I32),
                }],
            },
        );
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        let u = reg.union_def(34, "a.b.U").expect("overlay union");
        assert_eq!(u.fields.len(), 1);
        assert!(reg.union_def(34, "a.b.Missing").is_none());
    }

    #[test]
    fn enum_def_loads_from_overlay_and_aosp() {
        // overlay-provided enum
        let mut overlay = OverlayLayer {
            source_path: "x".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
        };
        overlay.enums.insert(
            "a.b.E".into(),
            EnumDef {
                fqn: "a.b.E".into(),
                backing: Prim::I32,
                consts: vec![("A".into(), 0)],
            },
        );
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        let e = reg.enum_def(34, "a.b.E").expect("overlay enum");
        assert_eq!(e.consts, vec![("A".into(), 0)]);
        assert!(reg.enum_def(34, "a.b.Missing").is_none());
    }

    #[test]
    fn bundled_native_corpus_resolves_isurfacecomposer_legacy() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);
        for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
            match reg.resolve(sdk, "android.ui.ISurfaceComposer", 1) {
                Lookup::Hit { method, .. } => {
                    assert_eq!(method.name, "bootFinished", "sdk={sdk}");
                }
                other => panic!(
                    "expected hit for android.ui.ISurfaceComposer at sdk={sdk}, got {:?}",
                    other
                ),
            }
        }
    }

    // raw String16 on the wire: int32 char_count + UTF-16 chars + u16 NUL, padded to 4.
    // matches Parcel::writeUtf8AsUtf16 / writeString16.
    fn s16(s: &str) -> Vec<u8> {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let mut b = (utf16.len() as i32).to_le_bytes().to_vec();
        for u in &utf16 {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0]); // u16 NUL
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn native_reg() -> Registry {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        Registry::empty().with_native_dir(&repo_root.join("data/native"))
    }

    fn igpu_method(reg: &Registry, sdk: u32, code: u32) -> &crate::model::Method {
        match reg.resolve(sdk, "android.graphicsenv.IGpuService", code) {
            Lookup::Hit { method, .. } => method,
            other => panic!("expected Hit for code {code}, got {other:?}"),
        }
    }

    #[test]
    fn decodes_native_igpuservice_set_gpu_stats() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        let method = igpu_method(&reg, 34, 1);
        assert_eq!(method.name, "setGpuStats");
        // BpGpuService::setGpuStats wire order.
        let mut buf = Vec::new();
        buf.extend_from_slice(&s16("pkg"));
        buf.extend_from_slice(&s16("1.2.3"));
        buf.extend_from_slice(&100i64.to_le_bytes()); // driverVersionCode (writeUint64 -> long)
        buf.extend_from_slice(&200i64.to_le_bytes()); // driverBuildTime
        buf.extend_from_slice(&s16("app"));
        buf.extend_from_slice(&7i32.to_le_bytes()); // vulkanVersion
        buf.extend_from_slice(&2i32.to_le_bytes()); // driver
        buf.extend_from_slice(&1i32.to_le_bytes()); // isDriverLoaded (writeBool -> int32 1)
        buf.extend_from_slice(&300i64.to_le_bytes()); // driverLoadingTime
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 9);
        assert_eq!(nodes[0].name, "driverPackageName");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "pkg"));
        assert!(matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "1.2.3"));
        assert!(matches!(nodes[2].value, DecodedValue::I64(100)));
        assert!(matches!(nodes[3].value, DecodedValue::I64(200)));
        assert!(matches!(&nodes[4].value, DecodedValue::Str(Some(s)) if s == "app"));
        assert!(matches!(nodes[5].value, DecodedValue::I64(7)));
        assert!(matches!(nodes[6].value, DecodedValue::I64(2)));
        assert!(matches!(nodes[7].value, DecodedValue::Bool(true)));
        assert!(matches!(nodes[8].value, DecodedValue::I64(300)));
    }

    #[test]
    fn decodes_native_igpuservice_set_target_stats() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        let method = igpu_method(&reg, 34, 2);
        assert_eq!(method.name, "setTargetStats");
        let mut buf = s16("app");
        buf.extend_from_slice(&50i64.to_le_bytes()); // driverVersionCode
        buf.extend_from_slice(&3i32.to_le_bytes()); // stats
        buf.extend_from_slice(&99i64.to_le_bytes()); // value
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 4);
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "app"));
        assert!(matches!(nodes[1].value, DecodedValue::I64(50)));
        assert!(matches!(nodes[2].value, DecodedValue::I64(3)));
        assert!(matches!(nodes[3].value, DecodedValue::I64(99)));
    }

    #[test]
    fn decodes_native_igpuservice_get_updatable_driver_path_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        let method = igpu_method(&reg, 34, 4);
        assert_eq!(method.name, "getUpdatableDriverPath");
        // native reply: bare String16, NO status header.
        let buf = s16("/vendor/lib/egl");
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "driverPath");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "/vendor/lib/egl"));
    }

    #[test]
    fn native_igpuservice_opaque_method_stays_name_only() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // code 7 = addVulkanEngineName, left as a typeless IBinder stub (no params).
        let method = igpu_method(&reg, 35, 7);
        assert_eq!(method.name, "addVulkanEngineName");
        assert!(method.params.is_empty());
        let nodes = decode_aidl_params(&reg, 35, method, &[], 0);
        assert!(nodes.is_empty());
    }

    fn native_method<'r>(
        reg: &'r Registry,
        sdk: u32,
        fqn: &str,
        code: u32,
    ) -> &'r crate::model::Method {
        match reg.resolve(sdk, fqn, code) {
            Lookup::Hit { method, .. } => method,
            other => panic!("expected Hit for {fqn} code={code} sdk={sdk}, got {other:?}"),
        }
    }

    #[test]
    fn decodes_native_imediaplayer_seek_to_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // seekTo(int msec, int mode, out int status) = 18
        let method = native_method(&reg, 34, "android.media.IMediaPlayer", 18);
        assert_eq!(method.name, "seekTo");
        // request parcel: msec=5000, mode=2 (SEEK_CLOSEST); out int status skipped by decoder
        let mut buf = Vec::new();
        buf.extend_from_slice(&5000i32.to_le_bytes()); // msec
        buf.extend_from_slice(&2i32.to_le_bytes()); // mode
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "msec");
        assert!(matches!(nodes[0].value, DecodedValue::I64(5000)));
        assert_eq!(nodes[1].name, "mode");
        assert!(matches!(nodes[1].value, DecodedValue::I64(2)));
    }

    #[test]
    fn decodes_native_imediaplayer_get_buffering_settings_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // getBufferingSettings(out int status, out int initialMarkMs, out int resumePlaybackMarkMs) = 8
        // reply wire order: status, initialMarkMs, resumePlaybackMarkMs
        let method = native_method(&reg, 34, "android.media.IMediaPlayer", 8);
        assert_eq!(method.name, "getBufferingSettings");
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes()); // status = OK
        buf.extend_from_slice(&1000i32.to_le_bytes()); // initialMarkMs
        buf.extend_from_slice(&2000i32.to_le_bytes()); // resumePlaybackMarkMs
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
        assert_eq!(nodes[1].name, "initialMarkMs");
        assert!(matches!(nodes[1].value, DecodedValue::I64(1000)));
        assert_eq!(nodes[2].name, "resumePlaybackMarkMs");
        assert!(matches!(nodes[2].value, DecodedValue::I64(2000)));
    }

    #[test]
    fn decodes_native_imediaplayer_set_playback_settings_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setPlaybackSettings(float speed, float pitch, int fallbackMode, int stretchMode, out int status) = 13
        let method = native_method(&reg, 34, "android.media.IMediaPlayer", 13);
        assert_eq!(method.name, "setPlaybackSettings");
        let mut buf = Vec::new();
        buf.extend_from_slice(&1.5f32.to_le_bytes()); // speed
        buf.extend_from_slice(&1.0f32.to_le_bytes()); // pitch
        buf.extend_from_slice(&0i32.to_le_bytes()); // fallbackMode
        buf.extend_from_slice(&1i32.to_le_bytes()); // stretchMode
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[0].name, "speed");
        assert!(matches!(nodes[0].value, DecodedValue::F64(v) if (v - 1.5f64).abs() < 1e-5));
        assert_eq!(nodes[1].name, "pitch");
        assert!(matches!(nodes[1].value, DecodedValue::F64(v) if (v - 1.0f64).abs() < 1e-5));
        assert!(matches!(nodes[2].value, DecodedValue::I64(0)));
        assert!(matches!(nodes[3].value, DecodedValue::I64(1)));
    }

    #[test]
    fn decodes_native_imediarecorder_set_video_size_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setVideoSize(int width, int height, out int status) = 18
        let method = native_method(&reg, 34, "android.media.IMediaRecorder", 18);
        assert_eq!(method.name, "setVideoSize");
        let mut buf = Vec::new();
        buf.extend_from_slice(&1920i32.to_le_bytes()); // width
        buf.extend_from_slice(&1080i32.to_le_bytes()); // height
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "width");
        assert!(matches!(nodes[0].value, DecodedValue::I64(1920)));
        assert_eq!(nodes[1].name, "height");
        assert!(matches!(nodes[1].value, DecodedValue::I64(1080)));
    }

    #[test]
    fn decodes_native_imediarecorder_get_max_amplitude_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // getMaxAmplitude(out int max, out int status) = 10
        // reply wire order: max, status
        let method = native_method(&reg, 34, "android.media.IMediaRecorder", 10);
        assert_eq!(method.name, "getMaxAmplitude");
        let mut buf = Vec::new();
        buf.extend_from_slice(&32767i32.to_le_bytes()); // max
        buf.extend_from_slice(&0i32.to_le_bytes()); // status = OK
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "max");
        assert!(matches!(nodes[0].value, DecodedValue::I64(32767)));
        assert_eq!(nodes[1].name, "status");
        assert!(matches!(nodes[1].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_native_imediarecorder_set_client_name_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setClientName(in String clientName, out int status) = 24
        let method = native_method(&reg, 34, "android.media.IMediaRecorder", 24);
        assert_eq!(method.name, "setClientName");
        let buf = s16("myapp");
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "clientName");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "myapp"));
    }

    #[test]
    fn decodes_native_imediarecorder_get_rtp_data_usage_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // getRtpDataUsage(out int status, out long bytes) = 33
        // reply wire order: status, bytes (readUint64 -> long)
        let method = native_method(&reg, 34, "android.media.IMediaRecorder", 33);
        assert_eq!(method.name, "getRtpDataUsage");
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes()); // status = OK
        buf.extend_from_slice(&12345678i64.to_le_bytes()); // bytes (readUint64 -> I64)
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
        assert_eq!(nodes[1].name, "bytes");
        assert!(matches!(nodes[1].value, DecodedValue::I64(12345678)));
    }

    #[test]
    fn decodes_native_imediaplayerservice_add_battery_data_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // addBatteryData(int params) = 4; no out params
        let method = native_method(&reg, 34, "android.media.IMediaPlayerService", 4);
        assert_eq!(method.name, "addBatteryData");
        let buf = 0x101i32.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "params");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0x101)));
    }

    #[test]
    fn decodes_native_imediarecorderclient_notify_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway notify(int msg, int ext1, int ext2) = 1
        let method = native_method(&reg, 34, "android.media.IMediaRecorderClient", 1);
        assert_eq!(method.name, "notify");
        assert!(method.oneway);
        let mut buf = Vec::new();
        buf.extend_from_slice(&7i32.to_le_bytes()); // msg = MEDIA_RECORDER_EVENT_INFO
        buf.extend_from_slice(&1i32.to_le_bytes()); // ext1
        buf.extend_from_slice(&0i32.to_le_bytes()); // ext2
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "msg");
        assert!(matches!(nodes[0].value, DecodedValue::I64(7)));
        assert_eq!(nodes[1].name, "ext1");
        assert!(matches!(nodes[1].value, DecodedValue::I64(1)));
        assert_eq!(nodes[2].name, "ext2");
        assert!(matches!(nodes[2].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_native_imediametadataretriever_disconnect_request() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // disconnect() = 1; no params, no out
        let method = native_method(&reg, 34, "android.media.IMediaMetadataRetriever", 1);
        assert_eq!(method.name, "disconnect");
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0);
        assert!(nodes.is_empty());
    }

    #[test]
    fn imediaplayer_android37_shifted_codes_resolve() {
        // android-37 inserted SET_VIDEO_SURFACETEXTURE_V2 at code 32, shifting 33-44.
        // Verify a few shifted methods resolve correctly by name.
        let reg = native_reg();
        let setNextPlayer = native_method(&reg, 37, "android.media.IMediaPlayer", 37);
        assert_eq!(setNextPlayer.name, "setNextPlayer");
        let enableCb = native_method(&reg, 37, "android.media.IMediaPlayer", 44);
        assert_eq!(enableCb.name, "enableAudioDeviceCallback");
        // code 32 is the new STUB
        let stub = native_method(&reg, 37, "android.media.IMediaPlayer", 32);
        assert_eq!(stub.name, "setVideoSurfaceTextureV2");
        assert!(stub.params.is_empty());
    }

    #[test]
    fn imediarecorder_android37_shifted_codes_resolve() {
        // android-37 inserted QUERY_SURFACE_MEDIASOURCE_V2 at code 6 and SET_PREVIEW_SURFACE_V2 at code 23.
        let reg = native_reg();
        let reset = native_method(&reg, 37, "android.media.IMediaRecorder", 7);
        assert_eq!(reset.name, "reset");
        let setCamera = native_method(&reg, 37, "android.media.IMediaRecorder", 24);
        assert_eq!(setCamera.name, "setCamera");
        let v2 = native_method(&reg, 37, "android.media.IMediaRecorder", 23);
        assert_eq!(v2.name, "setPreviewSurfaceV2");
        assert!(v2.params.is_empty());
    }
}

use crate::model::{EnumDef, Interface, Method, OverlayLayer, Parcelable, Union};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug)]
pub enum Lookup<'a> {
    Hit {
        method: &'a Method,
        source: Source<'a>,
    },
    UnknownInterface,
    UnknownCode {
        interface: &'a Interface,
    },
    SpecialCode(SpecialTxn),
}

#[derive(Debug, Clone, Copy)]
pub enum Source<'a> {
    Overlay(&'a Path),
    Lazy,
    /// Hit from the bundled synthetic `data/native/` corpus that ships
    /// AIDL stand-ins for hand-written C++ binder interfaces.
    Native,
}

pub struct Registry {
    overlays: Vec<OverlayLayer>,
    aosp_root: Option<PathBuf>,
    /// Synthetic native AIDL corpus, keyed by Android SDK level. The
    /// underlying C++ enums drift across releases (methods appended,
    /// occasionally renumbered) so the corpus mirrors the AOSP layout
    /// at one `Vec<OverlayLayer>` per `android-<sdk>/aidl/` subdir.
    native_layers: HashMap<u32, Vec<OverlayLayer>>,
    /// Cache for lazy loads. `None` value caches negative lookups so we
    /// don't re-stat / re-parse missing files. Box::leak'd so the
    /// `&'static Interface` borrow can outlive the RwLockReadGuard at
    /// resolve time.
    lazy_cache: RwLock<HashMap<(u32, String), Option<&'static Interface>>>,
    /// same as lazy_cache but for enums; None slots cache negative lookups.
    lazy_enum_cache: RwLock<HashMap<(u32, String), Option<&'static EnumDef>>>,
    /// same as lazy_cache but for parcelables; None slots cache negative lookups.
    lazy_parcelable_cache: RwLock<HashMap<(u32, String), Option<&'static Parcelable>>>,
    /// same as lazy_cache but for unions; None slots cache negative lookups.
    lazy_union_cache: RwLock<HashMap<(u32, String), Option<&'static Union>>>,
    /// fqn → file-path index, populated lazily once per SDK on first
    /// indirect lookup. The Option means we've populated for that SDK
    /// already (Some) or not yet (absent).
    fqn_index: RwLock<HashMap<u32, HashMap<String, PathBuf>>>,
}

impl Registry {
    pub fn empty() -> Self {
        Self::from_parts(vec![], None, HashMap::new())
    }

    pub fn from_parts(
        overlays: Vec<OverlayLayer>,
        aosp_root: Option<PathBuf>,
        native_layers: HashMap<u32, Vec<OverlayLayer>>,
    ) -> Self {
        Self {
            overlays,
            aosp_root,
            native_layers,
            lazy_cache: RwLock::new(HashMap::new()),
            lazy_enum_cache: RwLock::new(HashMap::new()),
            lazy_parcelable_cache: RwLock::new(HashMap::new()),
            lazy_union_cache: RwLock::new(HashMap::new()),
            fqn_index: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_aosp_dir(root: PathBuf) -> Self {
        Self::from_parts(vec![], Some(root), HashMap::new())
    }

    /// Walk `native_dir` looking for `android-<sdk>/aidl/` subtrees. Each
    /// such subtree becomes a `Vec<OverlayLayer>` keyed by its sdk number.
    /// SDKs without a matching subdir simply get no native layers.
    pub fn with_native_dir(mut self, native_dir: &Path) -> Self {
        let entries = match std::fs::read_dir(native_dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "binderdump-aidl: cannot read native corpus dir {}: {}",
                    native_dir.display(),
                    e
                );
                return self;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Some(sdk_str) = name_str.strip_prefix("android-") else {
                continue;
            };
            let Ok(sdk) = sdk_str.parse::<u32>() else {
                continue;
            };
            let aidl_subdir = entry.path().join("aidl");
            match Self::load_overlay_dir(&aidl_subdir) {
                Ok(layers) if !layers.is_empty() => {
                    self.native_layers.insert(sdk, layers);
                }
                Ok(_) => {
                    // aidl/ exists but has no parseable .aidl files — skip silently;
                    // an empty per-SDK dir is a valid intermediate state during backfill.
                }
                Err(e) => {
                    eprintln!(
                        "binderdump-aidl: cannot load native AIDL for sdk={}: {}",
                        sdk, e
                    );
                }
            }
        }
        if self.native_layers.is_empty() {
            eprintln!(
                "binderdump-aidl: native corpus dir {} contained no android-<sdk>/aidl/ subdirs",
                native_dir.display()
            );
        }
        self
    }

    pub fn resolve(&self, android_sdk: u32, fqn: &str, code: u32) -> Lookup<'_> {
        if let Some(s) = lookup_special(code) {
            return Lookup::SpecialCode(s);
        }

        // Overlays take precedence; iterate in reverse so last loaded wins.
        for overlay in self.overlays.iter().rev() {
            if let Some(iface) = overlay.interfaces.get(fqn) {
                return match iface.lookup(code) {
                    Some(m) => Lookup::Hit {
                        method: m,
                        source: Source::Overlay(&overlay.source_path),
                    },
                    None => Lookup::UnknownCode { interface: iface },
                };
            }
        }

        // Then AOSP lazy backend, if any. Only fall through to native layers
        // if AOSP has nothing for this fqn — an AOSP hit (Hit or UnknownCode)
        // must terminate so native synthetic AIDL never shadows real AOSP AIDL.
        if self.aosp_root.is_some() {
            let leaked = self.lazy_resolve_recursive(android_sdk, fqn);
            if leaked.is_some() {
                return self.materialize_lazy(leaked, code);
            }
        }

        // Native synthetic corpus as last resort before UnknownInterface.
        // Per-SDK: only the layers for this android_sdk are eligible.
        if let Some(layers) = self.native_layers.get(&android_sdk) {
            for layer in layers.iter() {
                if let Some(iface) = layer.interfaces.get(fqn) {
                    return match iface.lookup(code) {
                        Some(m) => Lookup::Hit {
                            method: m,
                            source: Source::Native,
                        },
                        None => Lookup::UnknownCode { interface: iface },
                    };
                }
            }
        }
        Lookup::UnknownInterface
    }

    fn lazy_load_one(&self, sdk: u32, fqn: &str) -> Option<Interface> {
        let root = self.aosp_root.as_ref()?;

        // helper: parse a candidate file as AIDL or HIDL based on extension
        let try_parse = |path: &Path| -> Option<Interface> {
            let src = std::fs::read_to_string(path).ok()?;
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            match ext {
                "aidl" => match crate::parser::aidl::parse_aidl(&src) {
                    Ok(parsed) => parsed.interfaces.into_iter().find(|i| i.fqn == fqn),
                    Err(e) => {
                        eprintln!(
                            "binderdump-aidl: lazy parse failed for {}: {:?}",
                            path.display(),
                            e
                        );
                        None
                    }
                },
                "hal" => match crate::parser::hidl::parse_hidl(&src) {
                    Ok(parsed) => {
                        let mut iface = parsed.into_iter().find(|i| i.fqn == fqn)?;
                        // resolve `extends` chain so base_code is correct
                        if let Some(parent_fqn) = iface.extends.clone() {
                            if let Some(parent) = self.lazy_resolve_recursive(sdk, &parent_fqn) {
                                iface.base_code = 1 + parent.methods.len() as u32;
                            }
                        }
                        Some(iface)
                    }
                    Err(e) => {
                        eprintln!(
                            "binderdump-hidl: lazy parse failed for {}: {}",
                            path.display(),
                            e
                        );
                        None
                    }
                },
                _ => None,
            }
        };

        // fast path: AIDL by dotted-fqn convention
        let aidl_path = crate::aosp_layout::aidl_path(root, sdk, fqn);
        if let Some(found) = try_parse(&aidl_path) {
            return Some(found);
        }

        // fast path: HIDL by versioned-fqn convention
        if let Some(hidl_path) = crate::aosp_layout::hidl_path(root, sdk, fqn) {
            if let Some(found) = try_parse(&hidl_path) {
                return Some(found);
            }
        }

        // slow path: build (or consult) per-SDK fqn→path index. Some files
        // live at AOSP source-tree paths that don't match the dotted/versioned
        // fqn convention (e.g. system/hardware/interfaces/suspend/aidl/...).
        self.populate_fqn_index(sdk);
        let candidate: Option<PathBuf> = {
            let idx = self.fqn_index.read().unwrap();
            idx.get(&sdk).and_then(|m| m.get(fqn)).cloned()
        };
        if let Some(path) = candidate {
            if let Some(found) = try_parse(&path) {
                return Some(found);
            }
        }

        None
    }

    fn populate_fqn_index(&self, sdk: u32) {
        // already populated?
        {
            let idx = self.fqn_index.read().unwrap();
            if idx.contains_key(&sdk) {
                return;
            }
        }
        let Some(root) = self.aosp_root.as_ref() else {
            return;
        };
        let sdk_dir = root.join(format!("android-{}", sdk));
        if !sdk_dir.exists() {
            self.fqn_index.write().unwrap().insert(sdk, HashMap::new());
            return;
        }

        let mut entries: HashMap<String, PathBuf> = HashMap::new();
        for entry in walkdir::WalkDir::new(&sdk_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            let Ok(src) = std::fs::read_to_string(path) else {
                continue;
            };
            match ext {
                "aidl" => {
                    for fqn in crate::aosp_layout::aidl_interfaces_in(&src) {
                        entries.entry(fqn).or_insert_with(|| path.to_path_buf());
                    }
                }
                "hal" => {
                    for fqn in crate::aosp_layout::hidl_interfaces_in(&src) {
                        entries.entry(fqn).or_insert_with(|| path.to_path_buf());
                    }
                }
                _ => {}
            }
        }
        eprintln!(
            "binderdump-aidl: indexed {} fqns for android-{}",
            entries.len(),
            sdk
        );
        self.fqn_index.write().unwrap().insert(sdk, entries);
    }

    fn lazy_resolve_recursive(&self, sdk: u32, fqn: &str) -> Option<&'static Interface> {
        {
            let cache = self.lazy_cache.read().unwrap();
            if let Some(slot) = cache.get(&(sdk, fqn.to_string())) {
                return *slot;
            }
        }
        let loaded = self.lazy_load_one(sdk, fqn);
        let leaked: Option<&'static Interface> = loaded.map(|i| &*Box::leak(Box::new(i)));
        self.lazy_cache
            .write()
            .unwrap()
            .insert((sdk, fqn.to_string()), leaked);
        leaked
    }

    // generic AOSP lazy load for a structured AIDL type: read-check the cache, else
    // resolve the file (fast aidl_path + slow fqn_index + enclosing-type fallback),
    // parse, `pick` the matching item, Box::leak to 'static, cache (None caches misses).
    fn lazy_typed<T: 'static>(
        &self,
        cache: &RwLock<HashMap<(u32, String), Option<&'static T>>>,
        sdk: u32,
        fqn: &str,
        pick: impl Fn(crate::parser::aidl::ParsedAidl) -> Option<T>,
    ) -> Option<&'static T> {
        {
            let c = cache.read().unwrap();
            if let Some(slot) = c.get(&(sdk, fqn.to_string())) {
                return *slot;
            }
        }
        let loaded = self.lazy_load_typed(sdk, fqn, &pick);
        let leaked: Option<&'static T> = loaded.map(|x| &*Box::leak(Box::new(x)));
        cache
            .write()
            .unwrap()
            .insert((sdk, fqn.to_string()), leaked);
        leaked
    }

    // parse the candidate aidl file(s) for `fqn` and `pick` the item, if any.
    // fast aidl_path + slow fqn_index + enclosing-type fallback (for nested types).
    fn lazy_load_typed<T>(
        &self,
        sdk: u32,
        fqn: &str,
        pick: &impl Fn(crate::parser::aidl::ParsedAidl) -> Option<T>,
    ) -> Option<T> {
        let root = self.aosp_root.as_ref()?;
        let find = |path: &Path| -> Option<T> {
            if path.extension().and_then(|s| s.to_str()) != Some("aidl") {
                return None;
            }
            let src = std::fs::read_to_string(path).ok()?;
            match crate::parser::aidl::parse_aidl(&src) {
                Ok(p) => pick(p),
                Err(_) => None,
            }
        };
        // fast path: dotted-fqn convention
        if let Some(x) = find(&crate::aosp_layout::aidl_path(root, sdk, fqn)) {
            return Some(x);
        }
        // slow path: per-sdk fqn->path index (nested types live in the enclosing file,
        // e.g. a.b.IFoo.Inner lives in IFoo.aidl).
        self.populate_fqn_index(sdk);
        let path = {
            let idx = self.fqn_index.read().unwrap();
            idx.get(&sdk).and_then(|m| m.get(fqn).cloned())
        };
        let candidates = path
            .into_iter()
            .chain(fqn.rsplit_once('.').and_then(|(outer, _)| {
                let idx = self.fqn_index.read().unwrap();
                idx.get(&sdk).and_then(|m| m.get(outer).cloned())
            }));
        for p in candidates {
            if let Some(x) = find(&p) {
                return Some(x);
            }
        }
        None
    }

    pub fn enum_def(&self, sdk: u32, fqn: &str) -> Option<&EnumDef> {
        for overlay in self.overlays.iter().rev() {
            if let Some(e) = overlay.enums.get(fqn) {
                return Some(e);
            }
        }
        if self.aosp_root.is_some() {
            let f = fqn.to_string();
            return self.lazy_typed(&self.lazy_enum_cache, sdk, fqn, move |p| {
                p.enums.into_iter().find(|e| e.fqn == f)
            });
        }
        None
    }

    pub fn parcelable_def(&self, sdk: u32, fqn: &str) -> Option<&Parcelable> {
        for overlay in self.overlays.iter().rev() {
            if let Some(p) = overlay.parcelables.get(fqn) {
                return Some(p);
            }
        }
        if self.aosp_root.is_some() {
            let f = fqn.to_string();
            return self.lazy_typed(&self.lazy_parcelable_cache, sdk, fqn, move |p| {
                p.parcelables.into_iter().find(|pc| pc.fqn == f)
            });
        }
        None
    }

    pub fn union_def(&self, sdk: u32, fqn: &str) -> Option<&Union> {
        for overlay in self.overlays.iter().rev() {
            if let Some(u) = overlay.unions.get(fqn) {
                return Some(u);
            }
        }
        if self.aosp_root.is_some() {
            let f = fqn.to_string();
            return self.lazy_typed(&self.lazy_union_cache, sdk, fqn, move |p| {
                p.unions.into_iter().find(|u| u.fqn == f)
            });
        }
        None
    }

    fn materialize_lazy(&self, slot: Option<&'static Interface>, code: u32) -> Lookup<'static> {
        match slot {
            None => Lookup::UnknownInterface,
            Some(iface) => match iface.lookup(code) {
                Some(m) => Lookup::Hit {
                    method: m,
                    source: Source::Lazy,
                },
                None => Lookup::UnknownCode { interface: iface },
            },
        }
    }

    pub fn load_overlay_dir(dir: &Path) -> std::io::Result<Vec<OverlayLayer>> {
        use crate::parser::{aidl::parse_aidl, hidl::parse_hidl};
        let mut layers = Vec::new();
        if !dir.exists() {
            return Ok(layers);
        }
        // HIDL `extends` may cross files, so collect every parsed hidl interface
        // into one bucket and resolve inheritance once across the whole set.
        // Each .hal contributes one OverlayLayer keyed on its source path.
        let mut hidl_pending: Vec<(PathBuf, Vec<Interface>)> = Vec::new();
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path: PathBuf = entry.path().to_path_buf();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            let src = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("binderdump-aidl: skip {}: {}", path.display(), e);
                    continue;
                }
            };
            match ext {
                "aidl" => match parse_aidl(&src) {
                    Ok(parsed) => {
                        eprintln!(
                            "binderdump-aidl: loaded {} interface(s) from {}",
                            parsed.interfaces.len(),
                            path.display()
                        );
                        layers.push(OverlayLayer {
                            source_path: path,
                            interfaces: parsed
                                .interfaces
                                .into_iter()
                                .map(|i| (i.fqn.clone(), i))
                                .collect(),
                            enums: parsed
                                .enums
                                .into_iter()
                                .map(|e| (e.fqn.clone(), e))
                                .collect(),
                            parcelables: parsed
                                .parcelables
                                .into_iter()
                                .map(|p| (p.fqn.clone(), p))
                                .collect(),
                            unions: parsed
                                .unions
                                .into_iter()
                                .map(|u| (u.fqn.clone(), u))
                                .collect(),
                        });
                    }
                    Err(_) => {
                        eprintln!("binderdump-aidl: failed to parse {}", path.display());
                        continue;
                    }
                },
                "hal" => match parse_hidl(&src) {
                    Ok(v) => {
                        eprintln!(
                            "binderdump-hidl: parsed {} interface(s) from {} (inheritance resolved across all .hal files)",
                            v.len(),
                            path.display()
                        );
                        hidl_pending.push((path, v));
                    }
                    Err(_) => {
                        eprintln!("binderdump-hidl: failed to parse {}", path.display());
                        continue;
                    }
                },
                _ => continue,
            }
        }

        if !hidl_pending.is_empty() {
            let all: Vec<Interface> = hidl_pending.iter().flat_map(|(_, v)| v.clone()).collect();
            match crate::parser::hidl::resolve_inheritance(all) {
                Ok(resolved) => {
                    let by_fqn: HashMap<String, Interface> =
                        resolved.into_iter().map(|i| (i.fqn.clone(), i)).collect();
                    for (path, parsed) in hidl_pending {
                        let mut interfaces = HashMap::new();
                        for iface in parsed {
                            if let Some(r) = by_fqn.get(&iface.fqn) {
                                interfaces.insert(iface.fqn, r.clone());
                            }
                        }
                        layers.push(OverlayLayer {
                            source_path: path,
                            interfaces,
                            enums: Default::default(),
                            parcelables: Default::default(),
                            unions: Default::default(),
                        });
                    }
                }
                Err(e) => eprintln!("binderdump-hidl: overlay inheritance error: {}", e),
            }
        }
        Ok(layers)
    }

    pub fn load_overlays_into(&mut self, dir: &Path) -> std::io::Result<()> {
        let layers = Self::load_overlay_dir(dir)?;
        self.overlays.extend(layers);
        Ok(())
    }

    pub fn overlay_count(&self) -> usize {
        self.overlays.len()
    }
}

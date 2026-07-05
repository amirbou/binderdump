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
            imports: vec![],
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
            typedefs: Default::default(),
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
            typedefs: Default::default(),
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
            typedefs: Default::default(),
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
            typedefs: Default::default(),
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
            typedefs: Default::default(),
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
            typedefs: Default::default(),
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

    #[test]
    fn bundled_native_corpus_resolves_isurfacecomposer_set_transaction_state() {
        // code 8 = setTransactionState; present and un-stubbed across all target SDKs.
        // non-oneway void; frameTimelineInfo is param 1, ComposerState[] is param 2.
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native_dir = repo_root.join("data/native");
        let reg = Registry::empty().with_native_dir(&native_dir);
        for sdk in [33u32, 34u32, 35u32, 36u32, 37u32] {
            match reg.resolve(sdk, "android.ui.ISurfaceComposer", 8) {
                Lookup::Hit { method, .. } => {
                    assert_eq!(method.name, "setTransactionState", "sdk={sdk}");
                    assert!(!method.oneway, "sdk={sdk}: expected non-oneway");
                }
                other => panic!(
                    "expected hit for android.ui.ISurfaceComposer code=8 at sdk={sdk}, got {:?}",
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

    // raw String8 on the wire: int32 byte_len + UTF-8 bytes + u8 NUL, padded to 4.
    // matches Parcel::writeString8.
    fn string8(s: &str) -> Vec<u8> {
        let mut b = (s.len() as i32).to_le_bytes().to_vec();
        b.extend_from_slice(s.as_bytes());
        b.push(0); // NUL
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    // raw CString on the wire: UTF-8 bytes + NUL, padded to 4. no length prefix.
    // matches Parcel::writeCString.
    fn cstring(s: &str) -> Vec<u8> {
        let mut b = s.as_bytes().to_vec();
        b.push(0); // NUL
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "driverPath");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "/vendor/lib/egl"));
    }

    #[test]
    fn decodes_native_igpuservice_add_vulkan_engine_name_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway void addVulkanEngineName(in CString engineName) = 7
        // BpGpuService::addVulkanEngineName calls writeCString, no length prefix.
        let method = igpu_method(&reg, 35, 7);
        assert_eq!(method.name, "addVulkanEngineName");
        assert!(method.oneway);
        let buf = cstring("ANGLE");
        let nodes = decode_aidl_params(&reg, 35, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "engineName");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "ANGLE"));
    }

    #[test]
    fn native_igpuservice_set_target_stats_array_stays_opaque() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // code 6 = setTargetStatsArray; ends in a raw Parcel::write() buffer — not
        // AIDL-expressible, stays as a typeless IBinder stub.
        let method = igpu_method(&reg, 35, 6);
        assert_eq!(method.name, "setTargetStatsArray");
        assert!(method.params.is_empty());
        let nodes = decode_aidl_params(&reg, 35, method, &[], 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
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
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0, &[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn imediaplayer_android37_shifted_codes_resolve() {
        // android-37 inserted SET_VIDEO_SURFACETEXTURE_V2 at code 32, shifting 33-44.
        // Verify a few shifted methods resolve correctly by name.
        let reg = native_reg();
        let set_next_player = native_method(&reg, 37, "android.media.IMediaPlayer", 37);
        assert_eq!(set_next_player.name, "setNextPlayer");
        let enable_cb = native_method(&reg, 37, "android.media.IMediaPlayer", 44);
        assert_eq!(enable_cb.name, "enableAudioDeviceCallback");
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

    // IRemoteDisplay

    #[test]
    fn decodes_native_iremotedisplay_dispose_request() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // dispose(out int status) = 1; no in params
        let method = native_method(&reg, 34, "android.media.IRemoteDisplay", 1);
        assert_eq!(method.name, "dispose");
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0, &[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn decodes_native_iremotedisplay_dispose_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // dispose(out int status) = 1; reply: readInt32() (status_t)
        let method = native_method(&reg, 34, "android.media.IRemoteDisplay", 1);
        assert_eq!(method.name, "dispose");
        let buf = 0i32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_native_iremotedisplay_resume_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // resume(out int status) = 3; reply: readInt32()
        let method = native_method(&reg, 34, "android.media.IRemoteDisplay", 3);
        assert_eq!(method.name, "resume");
        let buf = (-1i32).to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(-1)));
    }

    // IDataSource

    #[test]
    fn decodes_native_idatasource_read_at_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // readAt(long offset, long size, out long result) = 2
        let method = native_method(&reg, 34, "android.media.IDataSource", 2);
        assert_eq!(method.name, "readAt");
        let mut buf = Vec::new();
        buf.extend_from_slice(&4096i64.to_le_bytes()); // offset
        buf.extend_from_slice(&512i64.to_le_bytes()); // size
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "offset");
        assert!(matches!(nodes[0].value, DecodedValue::I64(4096)));
        assert_eq!(nodes[1].name, "size");
        assert!(matches!(nodes[1].value, DecodedValue::I64(512)));
    }

    #[test]
    fn decodes_native_idatasource_read_at_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // readAt(long offset, long size, out long result) = 2; reply: readInt64() (ssize_t)
        let method = native_method(&reg, 34, "android.media.IDataSource", 2);
        assert_eq!(method.name, "readAt");
        let buf = 512i64.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "result");
        assert!(matches!(nodes[0].value, DecodedValue::I64(512)));
    }

    #[test]
    fn decodes_native_idatasource_close_request() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // close() = 4; no params, no reply
        let method = native_method(&reg, 34, "android.media.IDataSource", 4);
        assert_eq!(method.name, "close");
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0, &[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn decodes_native_idatasource_get_flags_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // getFlags(out int flags) = 5; reply: readUint32() -> int
        let method = native_method(&reg, 34, "android.media.IDataSource", 5);
        assert_eq!(method.name, "getFlags");
        let buf = 3u32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "flags");
        assert!(matches!(nodes[0].value, DecodedValue::I64(3)));
    }

    // IMediaExtractor

    #[test]
    fn decodes_native_imediaextractor_count_tracks_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // countTracks(out int count) = 1; reply: readUint32() truncated to int
        let method = native_method(&reg, 34, "android.media.IMediaExtractor", 1);
        assert_eq!(method.name, "countTracks");
        let buf = 4u32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "count");
        assert!(matches!(nodes[0].value, DecodedValue::I64(4)));
    }

    #[test]
    fn decodes_native_imediaextractor_flags_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // flags(out int flags) = 5; reply: readUint32()
        let method = native_method(&reg, 34, "android.media.IMediaExtractor", 5);
        assert_eq!(method.name, "flags");
        let buf = 1u32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "flags");
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
    }

    #[test]
    fn decodes_native_imediaextractor_set_entry_point_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setEntryPoint(int entryPoint) = 9; no reply reads
        let method = native_method(&reg, 34, "android.media.IMediaExtractor", 9);
        assert_eq!(method.name, "setEntryPoint");
        let buf = 2i32.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "entryPoint");
        assert!(matches!(nodes[0].value, DecodedValue::I64(2)));
    }

    // IMediaCodecList

    #[test]
    fn decodes_native_imediacodeclist_count_codecs_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // countCodecs(out int count) = 2; reply: readInt32() clamped to INT32_MAX
        let method = native_method(&reg, 34, "android.media.IMediaCodecList", 2);
        assert_eq!(method.name, "countCodecs");
        let buf = 42i32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "count");
        assert!(matches!(nodes[0].value, DecodedValue::I64(42)));
    }

    // IMediaLogService

    #[test]
    fn decodes_native_imedialogservice_request_merge_wakeup_request() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // requestMergeWakeup() = 3; no params, no reply
        let method = native_method(&reg, 34, "android.media.IMediaLogService", 3);
        assert_eq!(method.name, "requestMergeWakeup");
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0, &[]);
        assert!(nodes.is_empty());
    }

    // IRemoteDisplayClient

    #[test]
    fn decodes_native_iremotedisplayclient_on_display_disconnected_request() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // oneway onDisplayDisconnected() = 2; no params
        let method = native_method(&reg, 34, "android.media.IRemoteDisplayClient", 2);
        assert_eq!(method.name, "onDisplayDisconnected");
        assert!(method.oneway);
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0, &[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn decodes_native_iremotedisplayclient_on_display_error_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway onDisplayError(int error) = 3; request: writeInt32(error)
        let method = native_method(&reg, 34, "android.media.IRemoteDisplayClient", 3);
        assert_eq!(method.name, "onDisplayError");
        assert!(method.oneway);
        let buf = 5i32.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "error");
        assert!(matches!(nodes[0].value, DecodedValue::I64(5)));
    }

    #[test]
    fn iremotedisplayclient_android37_has_four_methods() {
        // android-37 adds ON_DISPLAY_CONNECTED_SURFACE (=4, STUB)
        let reg = native_reg();
        let m4 = native_method(&reg, 37, "android.media.IRemoteDisplayClient", 4);
        assert_eq!(m4.name, "onDisplayConnectedSurface");
        assert!(m4.params.is_empty()); // STUB
                                       // methods 2 and 3 still present with same names
        let m2 = native_method(&reg, 37, "android.media.IRemoteDisplayClient", 2);
        assert_eq!(m2.name, "onDisplayDisconnected");
        let m3 = native_method(&reg, 37, "android.media.IRemoteDisplayClient", 3);
        assert_eq!(m3.name, "onDisplayError");
    }

    // IConsumerListener

    #[test]
    fn decodes_iconsumerlistener_on_frame_dequeued_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway onFrameDequeued(long bufferId) = 6; wire: writeUint64(bufferId)
        let method = native_method(&reg, 34, "android.gui.IConsumerListener", 6);
        assert_eq!(method.name, "onFrameDequeued");
        assert!(method.oneway);
        let buf = 0x123456789abcdefu64.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "bufferId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(v) if v == 0x123456789abcdefu64 as i64));
    }

    #[test]
    fn decodes_iconsumerlistener_on_frame_cancelled_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway onFrameCancelled(long bufferId) = 7; wire: writeUint64(bufferId)
        let method = native_method(&reg, 34, "android.gui.IConsumerListener", 7);
        assert_eq!(method.name, "onFrameCancelled");
        assert!(method.oneway);
        let buf = 42u64.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "bufferId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(42)));
    }

    // IGraphicBufferConsumer

    #[test]
    fn decodes_igraphicbufferconsumer_detach_buffer_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void detachBuffer(int slot, out int status) = 2; req: writeInt32(slot)
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 2);
        assert_eq!(method.name, "detachBuffer");
        let buf = 3i32.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "slot");
        assert!(matches!(nodes[0].value, DecodedValue::I64(3)));
    }

    #[test]
    fn decodes_igraphicbufferconsumer_detach_buffer_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void detachBuffer(int slot, out int status) = 2; reply: readInt32() → status_t
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 2);
        let buf = 0i32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_igraphicbufferconsumer_get_released_buffers_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void getReleasedBuffers(out int status, out long slotMask) = 7
        // reply wire: readInt32() status, readUint64(slotMask)
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 7);
        assert_eq!(method.name, "getReleasedBuffers");
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes()); // status
        buf.extend_from_slice(&0b1010u64.to_le_bytes()); // slotMask
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
        assert_eq!(nodes[1].name, "slotMask");
        assert!(matches!(nodes[1].value, DecodedValue::I64(0b1010)));
    }

    #[test]
    fn decodes_igraphicbufferconsumer_set_default_buffer_size_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void setDefaultBufferSize(int width, int height, out int status) = 8
        // req: writeUint32(width), writeUint32(height)
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 8);
        assert_eq!(method.name, "setDefaultBufferSize");
        let mut buf = Vec::new();
        buf.extend_from_slice(&1920u32.to_le_bytes()); // width
        buf.extend_from_slice(&1080u32.to_le_bytes()); // height
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "width");
        assert!(matches!(nodes[0].value, DecodedValue::I64(1920)));
        assert_eq!(nodes[1].name, "height");
        assert!(matches!(nodes[1].value, DecodedValue::I64(1080)));
    }

    #[test]
    fn decodes_igraphicbufferconsumer_set_consumer_usage_bits_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void setConsumerUsageBits(long usage, out int status) = 14; req: writeUint64(usage)
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 14);
        assert_eq!(method.name, "setConsumerUsageBits");
        let buf = 0x300u64.to_le_bytes().to_vec(); // GRALLOC_USAGE_HW_TEXTURE | GRALLOC_USAGE_HW_RENDER
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "usage");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0x300)));
    }

    #[test]
    fn decodes_igraphicbufferconsumer_set_consumer_is_protected_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void setConsumerIsProtected(boolean isProtected, out int status) = 15; req: writeBool(isProtected)
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 15);
        assert_eq!(method.name, "setConsumerIsProtected");
        let buf = 1i32.to_le_bytes().to_vec(); // true
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "isProtected");
        assert!(matches!(nodes[0].value, DecodedValue::Bool(true)));
    }

    #[test]
    fn decodes_igraphicbufferconsumer_discard_free_buffers_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void discardFreeBuffers(out int status) = 19; reply: readInt32() → status_t
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 19);
        assert_eq!(method.name, "discardFreeBuffers");
        let buf = 0i32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_igraphicbufferconsumer_set_consumer_name_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void setConsumerName(in String8 name, out int status) = 11
        // request: writeString8(name); SafeInterface writes status_t to reply (skipped here)
        let method = native_method(&reg, 34, "android.gui.IGraphicBufferConsumer", 11);
        assert_eq!(method.name, "setConsumerName");
        let buf = string8("SurfaceView");
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "name");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "SurfaceView"));
    }

    // ITransactionComposerListener

    #[test]
    fn decodes_itransactioncomposerlistener_on_trusted_presentation_changed_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway onTrustedPresentationChanged(int id, boolean inTrustedPresentationState) = 4
        // req: writeInt32(id), writeBool(inTrustedPresentationState); SDK 34+
        let method = native_method(&reg, 34, "android.gui.ITransactionComposerListener", 4);
        assert_eq!(method.name, "onTrustedPresentationChanged");
        assert!(method.oneway);
        let mut buf = Vec::new();
        buf.extend_from_slice(&7i32.to_le_bytes()); // id
        buf.extend_from_slice(&1i32.to_le_bytes()); // inTrustedPresentationState = true
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "id");
        assert!(matches!(nodes[0].value, DecodedValue::I64(7)));
        assert_eq!(nodes[1].name, "inTrustedPresentationState");
        assert!(matches!(nodes[1].value, DecodedValue::Bool(true)));
    }

    #[test]
    fn decodes_itransactioncomposerlistener_on_transaction_queue_stalled_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway void onTransactionQueueStalled(in String8 reason) = 3
        // request: writeString8(reason); oneway — no reply
        let method = native_method(&reg, 34, "android.gui.ITransactionComposerListener", 3);
        assert_eq!(method.name, "onTransactionQueueStalled");
        assert!(method.oneway);
        let buf = string8("tx_queue_overflow");
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "reason");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "tx_queue_overflow"));
    }

    // SensorEventConnection

    #[test]
    fn decodes_sensoreventconnection_enable_disable_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void enableDisable(int handle, boolean enabled, long samplingPeriodNs,
        //   long maxBatchReportLatencyNs, int reservedFlags, out int status) = 2
        let method = native_method(&reg, 34, "android.gui.SensorEventConnection", 2);
        assert_eq!(method.name, "enableDisable");
        let mut buf = Vec::new();
        buf.extend_from_slice(&42i32.to_le_bytes()); // handle
        buf.extend_from_slice(&1i32.to_le_bytes()); // enabled = true (writeInt32)
        buf.extend_from_slice(&200_000_000i64.to_le_bytes()); // samplingPeriodNs = 200ms
        buf.extend_from_slice(&0i64.to_le_bytes()); // maxBatchReportLatencyNs
        buf.extend_from_slice(&0i32.to_le_bytes()); // reservedFlags
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 5);
        assert_eq!(nodes[0].name, "handle");
        assert!(matches!(nodes[0].value, DecodedValue::I64(42)));
        assert_eq!(nodes[1].name, "enabled");
        assert!(matches!(nodes[1].value, DecodedValue::Bool(true)));
        assert_eq!(nodes[2].name, "samplingPeriodNs");
        assert!(matches!(nodes[2].value, DecodedValue::I64(200_000_000)));
        assert_eq!(nodes[3].name, "maxBatchReportLatencyNs");
        assert!(matches!(nodes[3].value, DecodedValue::I64(0)));
        assert_eq!(nodes[4].name, "reservedFlags");
        assert!(matches!(nodes[4].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_sensoreventconnection_enable_disable_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // reply: readInt32() → status_t
        let method = native_method(&reg, 34, "android.gui.SensorEventConnection", 2);
        let buf = 0i32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_sensoreventconnection_set_event_rate_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void setEventRate(int handle, long ns, out int status) = 3
        // req: writeInt32(handle), writeInt64(ns)
        let method = native_method(&reg, 34, "android.gui.SensorEventConnection", 3);
        assert_eq!(method.name, "setEventRate");
        let mut buf = Vec::new();
        buf.extend_from_slice(&5i32.to_le_bytes()); // handle
        buf.extend_from_slice(&50_000_000i64.to_le_bytes()); // ns = 50ms
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "handle");
        assert!(matches!(nodes[0].value, DecodedValue::I64(5)));
        assert_eq!(nodes[1].name, "ns");
        assert!(matches!(nodes[1].value, DecodedValue::I64(50_000_000)));
    }

    #[test]
    fn decodes_sensoreventconnection_flush_sensor_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void flushSensor(out int status) = 4; reply: readInt32()
        let method = native_method(&reg, 34, "android.gui.SensorEventConnection", 4);
        assert_eq!(method.name, "flushSensor");
        let buf = (-1i32).to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(-1)));
    }

    #[test]
    fn decodes_sensoreventconnection_destroy_is_oneway_no_reply() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // oneway destroy() = 6; no params, no reply
        let method = native_method(&reg, 34, "android.gui.SensorEventConnection", 6);
        assert_eq!(method.name, "destroy");
        assert!(method.oneway);
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0, &[]);
        assert!(nodes.is_empty());
    }

    // SensorServer

    #[test]
    fn decodes_sensorserver_enable_data_injection_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void enableDataInjection(int mode, out int status) = 3; req: writeInt32(mode)
        let method = native_method(&reg, 34, "android.gui.SensorServer", 3);
        assert_eq!(method.name, "enableDataInjection");
        let buf = 1i32.to_le_bytes().to_vec(); // mode = 1 (enable)
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "mode");
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
    }

    #[test]
    fn decodes_sensorserver_enable_data_injection_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void enableDataInjection(int mode, out int status) = 3; reply: readInt32()
        let method = native_method(&reg, 34, "android.gui.SensorServer", 3);
        let buf = 0i32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_sensorserver_enable_replay_data_injection_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void enableReplayDataInjection(int mode, out int status) = 8; SDK 35+
        let method = native_method(&reg, 35, "android.gui.SensorServer", 8);
        assert_eq!(method.name, "enableReplayDataInjection");
        let buf = 1i32.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 35, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "mode");
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
    }

    #[test]
    fn sensorserver_sdk33_has_six_methods() {
        let reg = native_reg();
        // sdk 33 has codes 1–6; 7–9 absent
        assert!(matches!(
            reg.resolve(33, "android.gui.SensorServer", 6),
            Lookup::Hit { .. }
        ));
        assert!(matches!(
            reg.resolve(33, "android.gui.SensorServer", 7),
            Lookup::UnknownCode { .. }
        ));
    }

    #[test]
    fn sensorserver_sdk35_has_nine_methods() {
        let reg = native_reg();
        // sdk 35 has codes 1–9
        let m8 = native_method(&reg, 35, "android.gui.SensorServer", 8);
        assert_eq!(m8.name, "enableReplayDataInjection");
        let m9 = native_method(&reg, 35, "android.gui.SensorServer", 9);
        assert_eq!(m9.name, "enableHalBypassReplayDataInjection");
    }

    #[test]
    fn decodes_sensorserver_create_sensor_event_connection_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void createSensorEventConnection(in String8 packageName, int mode,
        //   in String opPackageName, in String attributionTag, out IBinder connection) = 2
        // request: writeString8(packageName), writeInt32(mode),
        //   writeString16(opPackageName), writeString16(attributionTag)
        // reply: readStrongBinder (out IBinder connection) — skipped by decode_aidl_params
        let method = native_method(&reg, 34, "android.gui.SensorServer", 2);
        assert_eq!(method.name, "createSensorEventConnection");
        let mut buf = Vec::new();
        buf.extend_from_slice(&string8("com.example.app")); // packageName (String8)
        buf.extend_from_slice(&0i32.to_le_bytes()); // mode = 0 (normal)
        buf.extend_from_slice(&s16("com.example")); // opPackageName (String16)
        buf.extend_from_slice(&s16("sensors")); // attributionTag (String16)
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[0].name, "packageName");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "com.example.app"));
        assert_eq!(nodes[1].name, "mode");
        assert!(matches!(nodes[1].value, DecodedValue::I64(0)));
        assert_eq!(nodes[2].name, "opPackageName");
        assert!(matches!(&nodes[2].value, DecodedValue::Str(Some(s)) if s == "com.example"));
        assert_eq!(nodes[3].name, "attributionTag");
        assert!(matches!(&nodes[3].value, DecodedValue::Str(Some(s)) if s == "sensors"));
    }

    // ICameraRecordingProxy

    #[test]
    fn decodes_icamerarecordingproxy_start_recording_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // startRecording(out int status) = 1; no in params; reply: readInt32() → status_t
        let method = native_method(&reg, 34, "android.hardware.ICameraRecordingProxy", 1);
        assert_eq!(method.name, "startRecording");
        let buf = 0i32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_icamerarecordingproxy_stop_recording_request() {
        use crate::decode::decode_aidl_params;
        let reg = native_reg();
        // stopRecording() = 2; no in params, reply parcel is empty
        let method = native_method(&reg, 34, "android.hardware.ICameraRecordingProxy", 2);
        assert_eq!(method.name, "stopRecording");
        let nodes = decode_aidl_params(&reg, 34, method, &[], 0, &[]);
        assert!(nodes.is_empty());
    }

    // ICameraRecordingProxyListener

    #[test]
    fn decodes_icamerarecordingproxylistener_data_callback_timestamp_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway dataCallbackTimestamp(long timestamp, int msgType, in IBinder imageData) = 1
        // IBinder imageData halts decoding — timestamp and msgType are decodable.
        let method = native_method(
            &reg,
            34,
            "android.hardware.ICameraRecordingProxyListener",
            1,
        );
        assert_eq!(method.name, "dataCallbackTimestamp");
        assert!(method.oneway);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1_000_000_000i64.to_le_bytes()); // timestamp = 1s in ns
        buf.extend_from_slice(&1i32.to_le_bytes()); // msgType = CAMERA_MSG_VIDEO_FRAME
                                                    // imageData (IBinder) — undecodable; raw bytes follow
        buf.extend_from_slice(&[0u8; 4]); // placeholder binder bytes
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "timestamp");
        assert!(matches!(nodes[0].value, DecodedValue::I64(1_000_000_000)));
        assert_eq!(nodes[1].name, "msgType");
        assert!(matches!(nodes[1].value, DecodedValue::I64(1)));
        assert_eq!(nodes[2].name, "imageData");
        assert!(matches!(nodes[2].value, DecodedValue::RawTail { .. }));
    }

    // IStreamSource

    #[test]
    fn decodes_istreamsource_on_buffer_available_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway onBufferAvailable(long index) = 3; req: writeInt64(index)
        let method = native_method(&reg, 34, "android.hardware.IStreamSource", 3);
        assert_eq!(method.name, "onBufferAvailable");
        assert!(method.oneway);
        let buf = 2i64.to_le_bytes().to_vec();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "index");
        assert!(matches!(nodes[0].value, DecodedValue::I64(2)));
    }

    #[test]
    fn decodes_istreamsource_flags_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // flags(out int flags) = 4; reply: readInt32() → uint32_t flags
        let method = native_method(&reg, 34, "android.hardware.IStreamSource", 4);
        assert_eq!(method.name, "flags");
        let buf = 3u32.to_le_bytes().to_vec();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "flags");
        assert!(matches!(nodes[0].value, DecodedValue::I64(3)));
    }

    #[test]
    fn decodes_istreamsource_set_buffers_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setBuffers(long count, in IBinder buffers) = 2
        // wire: writeInt64(count) then N binders inline; IBinder halts after count.
        let method = native_method(&reg, 34, "android.hardware.IStreamSource", 2);
        assert_eq!(method.name, "setBuffers");
        let mut buf = Vec::new();
        buf.extend_from_slice(&3i64.to_le_bytes()); // count = 3
        buf.extend_from_slice(&[0u8; 16]); // placeholder binder data
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "count");
        assert!(matches!(nodes[0].value, DecodedValue::I64(3)));
        assert_eq!(nodes[1].name, "buffers");
        assert!(matches!(nodes[1].value, DecodedValue::RawTail { .. }));
    }

    // IStreamListener

    #[test]
    fn decodes_istreamlistener_queue_buffer_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway queueBuffer(long index, long size) = 5; req: writeInt64(index), writeInt64(size)
        let method = native_method(&reg, 34, "android.hardware.IStreamListener", 5);
        assert_eq!(method.name, "queueBuffer");
        assert!(method.oneway);
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i64.to_le_bytes()); // index = 0
        buf.extend_from_slice(&4096i64.to_le_bytes()); // size = 4096
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "index");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
        assert_eq!(nodes[1].name, "size");
        assert!(matches!(nodes[1].value, DecodedValue::I64(4096)));
    }

    // ISurfaceComposer

    #[test]
    fn decodes_isurfacecomposer_enable_vsync_injections_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway void enableVsyncInjections(boolean enable) = 24
        let method = native_method(&reg, 34, "android.ui.ISurfaceComposer", 24);
        assert_eq!(method.name, "enableVsyncInjections");
        assert!(method.oneway);
        let buf = 1i32.to_le_bytes(); // writeBool(true) -> int32 1
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "enable");
        assert!(matches!(nodes[0].value, DecodedValue::Bool(true)));
    }

    #[test]
    fn decodes_isurfacecomposer_inject_vsync_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // oneway void injectVsync(long when) = 25
        let method = native_method(&reg, 34, "android.ui.ISurfaceComposer", 25);
        assert_eq!(method.name, "injectVsync");
        assert!(method.oneway);
        let buf = 123_456_789i64.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "when");
        assert!(matches!(nodes[0].value, DecodedValue::I64(123_456_789)));
    }

    #[test]
    fn decodes_isurfacecomposer_get_composition_preference_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void getCompositionPreference(out int status, out int defaultDataspace,
        //   out int defaultPixelFormat, out int wideColorGamutDataspace,
        //   out int wideColorGamutPixelFormat) = 27
        let method = native_method(&reg, 34, "android.ui.ISurfaceComposer", 27);
        assert_eq!(method.name, "getCompositionPreference");
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes()); // status = OK
        buf.extend_from_slice(&143i32.to_le_bytes()); // defaultDataspace
        buf.extend_from_slice(&1i32.to_le_bytes()); // defaultPixelFormat
        buf.extend_from_slice(&144i32.to_le_bytes()); // wideColorGamutDataspace
        buf.extend_from_slice(&4i32.to_le_bytes()); // wideColorGamutPixelFormat
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 5);
        assert_eq!(nodes[0].name, "status");
        assert!(matches!(nodes[0].value, DecodedValue::I64(0)));
        assert_eq!(nodes[1].name, "defaultDataspace");
        assert!(matches!(nodes[1].value, DecodedValue::I64(143)));
        assert_eq!(nodes[2].name, "defaultPixelFormat");
        assert_eq!(nodes[3].name, "wideColorGamutDataspace");
        assert_eq!(nodes[4].name, "wideColorGamutPixelFormat");
    }

    #[test]
    fn decodes_isurfacecomposer_get_color_management_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void getColorManagement(out boolean colorManagement) = 28
        let method = native_method(&reg, 34, "android.ui.ISurfaceComposer", 28);
        assert_eq!(method.name, "getColorManagement");
        let buf = 1i32.to_le_bytes(); // writeBool(true) -> int32 1
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "colorManagement");
        assert!(matches!(nodes[0].value, DecodedValue::Bool(true)));
    }

    #[test]
    fn decodes_isurfacecomposer_get_desired_display_mode_specs_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void getDesiredDisplayModeSpecs(IBinder token,
        //   out int defaultMode, out boolean allowGroupSwitching,
        //   out float primaryRefreshRateMin, out float primaryRefreshRateMax,
        //   out float appRequestRefreshRateMin, out float appRequestRefreshRateMax,
        //   out int status) = 39
        // reply wire: defaultMode, allowGroupSwitching, 4×float, status (status last per C++ source)
        let method = native_method(&reg, 34, "android.ui.ISurfaceComposer", 39);
        assert_eq!(method.name, "getDesiredDisplayModeSpecs");
        let mut buf = Vec::new();
        buf.extend_from_slice(&2i32.to_le_bytes()); // defaultMode = 2
        buf.extend_from_slice(&0i32.to_le_bytes()); // allowGroupSwitching = false
        buf.extend_from_slice(&60.0f32.to_le_bytes()); // primaryRefreshRateMin
        buf.extend_from_slice(&120.0f32.to_le_bytes()); // primaryRefreshRateMax
        buf.extend_from_slice(&30.0f32.to_le_bytes()); // appRequestRefreshRateMin
        buf.extend_from_slice(&120.0f32.to_le_bytes()); // appRequestRefreshRateMax
        buf.extend_from_slice(&0i32.to_le_bytes()); // status = OK
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 7);
        assert_eq!(nodes[0].name, "defaultMode");
        assert!(matches!(nodes[0].value, DecodedValue::I64(2)));
        assert_eq!(nodes[1].name, "allowGroupSwitching");
        assert!(matches!(nodes[1].value, DecodedValue::Bool(false)));
        assert_eq!(nodes[2].name, "primaryRefreshRateMin");
        assert!(matches!(nodes[2].value, DecodedValue::F64(v) if (v - 60.0).abs() < 1e-3));
        assert_eq!(nodes[6].name, "status");
        assert!(matches!(nodes[6].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_isurfacecomposer_create_display_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void createDisplay(in String8 displayName, boolean secure, out IBinder display) = 5
        // BpSurfaceComposer::createDisplay: writeString8(displayName), writeBool(secure).
        let method = native_method(&reg, 34, "android.ui.ISurfaceComposer", 5);
        assert_eq!(method.name, "createDisplay");
        let mut buf = string8("ExternalDisplay");
        buf.extend_from_slice(&1i32.to_le_bytes()); // writeBool(secure=true) → int32 1
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "displayName");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "ExternalDisplay"));
        assert_eq!(nodes[1].name, "secure");
        assert!(matches!(nodes[1].value, DecodedValue::Bool(true)));
    }

    #[test]
    fn decodes_isurfacecomposer_create_display_reply() {
        use crate::binder_object;
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void createDisplay(in String8 displayName, boolean secure, out IBinder display) = 5
        // reply: readStrongBinder() -> display token (sp<IBinder>)
        let method = native_method(&reg, 34, "android.ui.ISurfaceComposer", 5);
        assert_eq!(method.name, "createDisplay");
        let mut buf = Vec::new();
        let binder_off = buf.len() as u64;
        buf.extend_from_slice(&binder_object::HANDLE.to_le_bytes()); // type
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&7u64.to_le_bytes()); // handle = 7
        buf.extend_from_slice(&0u64.to_le_bytes()); // cookie
        let offsets = binder_off.to_le_bytes();
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &offsets);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "display");
        assert!(matches!(
            nodes[0].value,
            DecodedValue::Binder {
                handle: 7,
                strong: false
            }
        ));
    }

    // IDrmManagerService

    #[test]
    fn decodes_idrm_manager_service_remove_all_rights_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // void removeAllRights(int uniqueId, out int status) = 20
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 20);
        assert_eq!(method.name, "removeAllRights");
        let buf = 99i32.to_le_bytes(); // uniqueId = 99
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(99)));
    }

    #[test]
    fn decodes_idrm_manager_service_add_unique_id_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_reg();
        // void addUniqueId(int isNative, out int uniqueId) = 1
        // reply: readInt32 -> uniqueId
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 1);
        assert_eq!(method.name, "addUniqueId");
        let buf = 7i32.to_le_bytes(); // uniqueId = 7
        let nodes = decode_native_reply(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(7)));
    }

    // IMediaExtractor — String8

    #[test]
    fn decodes_native_imediaextractor_set_log_session_id_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setLogSessionId(in String8 sessionId) = 10; no out params on request
        let method = native_method(&reg, 34, "android.media.IMediaExtractor", 10);
        assert_eq!(method.name, "setLogSessionId");
        let buf = string8("abc-session-123");
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "sessionId");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "abc-session-123"));
    }

    // IMediaCodecList — CString

    #[test]
    fn decodes_native_imediacodeclist_find_codec_by_type_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // findCodecByType(in CString type, int encoder, int startIndex, out int result) = 5
        let method = native_method(&reg, 34, "android.media.IMediaCodecList", 5);
        assert_eq!(method.name, "findCodecByType");
        let mut buf = cstring("video/avc"); // 9 chars+NUL=10, padded to 12
        buf.extend_from_slice(&1i32.to_le_bytes()); // encoder = 1
        buf.extend_from_slice(&0i32.to_le_bytes()); // startIndex = 0
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "type");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "video/avc"));
        assert_eq!(nodes[1].name, "encoder");
        assert!(matches!(nodes[1].value, DecodedValue::I64(1)));
        assert_eq!(nodes[2].name, "startIndex");
        assert!(matches!(nodes[2].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_native_imediacodeclist_find_codec_by_name_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // findCodecByName(in CString name, out int result) = 6
        let method = native_method(&reg, 34, "android.media.IMediaCodecList", 6);
        assert_eq!(method.name, "findCodecByName");
        let buf = cstring("OMX.google.avc.decoder");
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "name");
        assert!(
            matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "OMX.google.avc.decoder")
        );
    }

    // IMediaPlayerService — String8 + IBinder

    #[test]
    fn decodes_native_imediaplayerservice_listen_for_remote_display_request() {
        use crate::binder_object;
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // listenForRemoteDisplay(in String opPackageName, in IBinder client,
        //   in String8 iface, out IBinder display) = 6
        // request: writeString16(opPackageName), flat_binder_object(client), writeString8(iface)
        let method = native_method(&reg, 34, "android.media.IMediaPlayerService", 6);
        assert_eq!(method.name, "listenForRemoteDisplay");
        let mut buf = Vec::new();
        buf.extend_from_slice(&s16("com.example")); // opPackageName (String16)
        let binder_off = buf.len() as u64; // offset of the flat_binder_object
        buf.extend_from_slice(&binder_object::HANDLE.to_le_bytes()); // type
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&3u64.to_le_bytes()); // handle = 3
        buf.extend_from_slice(&0u64.to_le_bytes()); // cookie
        buf.extend_from_slice(&string8("wlan0")); // iface (String8)
        let offsets = binder_off.to_le_bytes();
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &offsets);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "opPackageName");
        assert!(matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "com.example"));
        assert_eq!(nodes[1].name, "client");
        assert!(matches!(
            nodes[1].value,
            DecodedValue::Binder {
                handle: 3,
                strong: false
            }
        ));
        assert_eq!(nodes[2].name, "iface");
        assert!(matches!(&nodes[2].value, DecodedValue::Str(Some(s)) if s == "wlan0"));
    }

    // IMediaPlayer — String8

    #[test]
    fn decodes_native_imediaplayer_set_data_source_rtp_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setDataSourceRtp(in String8 rtpParams, out int status) = 6
        let method = native_method(&reg, 34, "android.media.IMediaPlayer", 6);
        assert_eq!(method.name, "setDataSourceRtp");
        let buf = string8("rtp://192.168.1.1:5004");
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "rtpParams");
        assert!(
            matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "rtp://192.168.1.1:5004")
        );
    }

    // IMediaRecorder — String8

    #[test]
    fn decodes_native_imediarecorder_set_parameters_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // setParameters(in String8 params, out int status) = 20 (sdk 33-36), 21 (sdk 37)
        for (sdk, code) in [(33u32, 20u32), (34, 20), (35, 20), (36, 20), (37, 21)] {
            let method = native_method(&reg, sdk, "android.media.IMediaRecorder", code);
            assert_eq!(method.name, "setParameters", "sdk={sdk}");
            let buf = string8("time-lapse-fps=30&video-bitrate=4000000");
            let nodes = decode_aidl_params(&reg, sdk, method, &buf, 0, &[]);
            assert_eq!(nodes.len(), 1, "sdk={sdk}");
            assert_eq!(nodes[0].name, "params", "sdk={sdk}");
            assert!(
                matches!(&nodes[0].value, DecodedValue::Str(Some(s)) if s == "time-lapse-fps=30&video-bitrate=4000000"),
                "sdk={sdk}"
            );
        }
    }

    // IDrmManagerService — String8

    #[test]
    fn decodes_idrm_can_handle_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // canHandle(int uniqueId, in String8 path, in String8 mimeType, out int result) = 9
        // request: writeInt32(uniqueId), writeString8(path), writeString8(mimeType)
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 9);
        assert_eq!(method.name, "canHandle");
        let mut buf = Vec::new();
        buf.extend_from_slice(&42i32.to_le_bytes()); // uniqueId
        buf.extend_from_slice(&string8("/sdcard/movie.mp4")); // path
        buf.extend_from_slice(&string8("video/mp4")); // mimeType
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(42)));
        assert_eq!(nodes[1].name, "path");
        assert!(matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "/sdcard/movie.mp4"));
        assert_eq!(nodes[2].name, "mimeType");
        assert!(matches!(&nodes[2].value, DecodedValue::Str(Some(s)) if s == "video/mp4"));
    }

    #[test]
    fn decodes_idrm_get_drm_object_type_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // getDrmObjectType(int uniqueId, in String8 path, in String8 mimeType, out int objectType) = 14
        // request: writeInt32(uniqueId), writeString8(path), writeString8(mimeType)
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 14);
        assert_eq!(method.name, "getDrmObjectType");
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes()); // uniqueId
        buf.extend_from_slice(&string8("/sdcard/rights.dcf")); // path
        buf.extend_from_slice(&string8("application/vnd.oma.drm.content")); // mimeType
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(1)));
        assert_eq!(nodes[1].name, "path");
        assert!(matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "/sdcard/rights.dcf"));
        assert_eq!(nodes[2].name, "mimeType");
        assert!(
            matches!(&nodes[2].value, DecodedValue::Str(Some(s)) if s == "application/vnd.oma.drm.content")
        );
    }

    #[test]
    fn decodes_idrm_check_rights_status_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // checkRightsStatus(int uniqueId, in String8 path, int action, out int result) = 15
        // request: writeInt32(uniqueId), writeString8(path), writeInt32(action)
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 15);
        assert_eq!(method.name, "checkRightsStatus");
        let mut buf = Vec::new();
        buf.extend_from_slice(&3i32.to_le_bytes()); // uniqueId
        buf.extend_from_slice(&string8("/sdcard/content.dcf")); // path
        buf.extend_from_slice(&1i32.to_le_bytes()); // action = Action::PLAY
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(3)));
        assert_eq!(nodes[1].name, "path");
        assert!(
            matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "/sdcard/content.dcf")
        );
        assert_eq!(nodes[2].name, "action");
        assert!(matches!(nodes[2].value, DecodedValue::I64(1)));
    }

    #[test]
    fn decodes_idrm_validate_action_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // validateAction(int uniqueId, in String8 path, int action,
        //   int outputType, int configuration, out int result) = 18
        // request: writeInt32(uniqueId), writeString8(path), writeInt32(action),
        //   writeInt32(description.outputType), writeInt32(description.configuration)
        // ActionDescription is a flat struct written as two bare int32s.
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 18);
        assert_eq!(method.name, "validateAction");
        let mut buf = Vec::new();
        buf.extend_from_slice(&2i32.to_le_bytes()); // uniqueId
        buf.extend_from_slice(&string8("/sdcard/protected.dcf")); // path
        buf.extend_from_slice(&2i32.to_le_bytes()); // action = Action::TRANSFER
        buf.extend_from_slice(&1i32.to_le_bytes()); // outputType
        buf.extend_from_slice(&0i32.to_le_bytes()); // configuration
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 5);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(2)));
        assert_eq!(nodes[1].name, "path");
        assert!(
            matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "/sdcard/protected.dcf")
        );
        assert_eq!(nodes[2].name, "action");
        assert!(matches!(nodes[2].value, DecodedValue::I64(2)));
        assert_eq!(nodes[3].name, "outputType");
        assert!(matches!(nodes[3].value, DecodedValue::I64(1)));
        assert_eq!(nodes[4].name, "configuration");
        assert!(matches!(nodes[4].value, DecodedValue::I64(0)));
    }

    #[test]
    fn decodes_idrm_remove_rights_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // removeRights(int uniqueId, in String8 path, out int status) = 19
        // request: writeInt32(uniqueId), writeString8(path)
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 19);
        assert_eq!(method.name, "removeRights");
        let mut buf = Vec::new();
        buf.extend_from_slice(&7i32.to_le_bytes()); // uniqueId
        buf.extend_from_slice(&string8("/sdcard/movie.fl")); // path
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(7)));
        assert_eq!(nodes[1].name, "path");
        assert!(matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "/sdcard/movie.fl"));
    }

    #[test]
    fn decodes_idrm_open_convert_session_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_reg();
        // openConvertSession(int uniqueId, in String8 mimeType, out int convertId) = 21
        // request: writeInt32(uniqueId), writeString8(mimeType)
        let method = native_method(&reg, 34, "drm.IDrmManagerService", 21);
        assert_eq!(method.name, "openConvertSession");
        let mut buf = Vec::new();
        buf.extend_from_slice(&5i32.to_le_bytes()); // uniqueId
        buf.extend_from_slice(&string8("application/vnd.oma.drm.content")); // mimeType
        let nodes = decode_aidl_params(&reg, 34, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "uniqueId");
        assert!(matches!(nodes[0].value, DecodedValue::I64(5)));
        assert_eq!(nodes[1].name, "mimeType");
        assert!(
            matches!(&nodes[1].value, DecodedValue::Str(Some(s)) if s == "application/vnd.oma.drm.content")
        );
    }

    // loads both the AOSP corpus (for parcelable/enum definitions) and the
    // native synthetic corpus (for hand-written C++ interface stubs).
    fn native_and_aosp_reg() -> Registry {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        Registry::with_aosp_dir(repo_root.join("data/aosp"))
            .with_native_dir(&repo_root.join("data/native"))
    }

    // helper for building a writeParcelable buffer: [int32 1][int32 size][fields].
    // size counts itself (4 bytes) + the provided field bytes.
    fn parcelable_buf(fields: &[u8]) -> Vec<u8> {
        let size = 4 + fields.len(); // size header counts itself
        let mut b = Vec::new();
        b.extend_from_slice(&1i32.to_le_bytes()); // presence flag (C++ writeParcelable)
        b.extend_from_slice(&(size as i32).to_le_bytes());
        b.extend_from_slice(fields);
        b
    }

    // verify decode_parcelable_arg handles C++ writeParcelable wire format
    // [int32 1 (presence flag)][int32 size][fields] without corpus lookup for
    // the interface — only the AOSP parcelable definition is needed.
    #[test]
    fn decodes_writeparcelable_presence_flag() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_and_aosp_reg();
        // build the method inline: create(in android.content.AttributionSourceState attributionSource)
        let method = Method {
            name: "create".to_string(),
            params: vec![Parameter {
                name: "attributionSource".to_string(),
                ty: TypeRef::UserDefined("android.content.AttributionSourceState".to_string()),
                direction: Direction::In,
            }],
            return_type: Some(TypeRef::IBinder),
            oneway: false,
            code: Some(1),
        };
        // [int32 1 (presence)][int32 12 (size: 4+4+4)][int32 -1 (pid)][int32 1000 (uid)]
        // size=12 means boundary lands after uid — trailing fields truncated.
        let mut fields = Vec::new();
        fields.extend_from_slice(&(-1i32).to_le_bytes()); // pid
        fields.extend_from_slice(&1000i32.to_le_bytes()); // uid
        let buf = parcelable_buf(&fields);
        let nodes = decode_aidl_params(&reg, 35, &method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "attributionSource");
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "android.content.AttributionSourceState"
        ));
        assert!(nodes[0].children.len() >= 2);
        assert_eq!(nodes[0].children[0].name, "pid");
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(-1)));
        assert_eq!(nodes[0].children[1].name, "uid");
        assert!(matches!(
            nodes[0].children[1].value,
            DecodedValue::I64(1000)
        ));
    }

    #[test]
    fn decodes_native_imediaplayerservice_create_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_and_aosp_reg();
        // create(in android.content.AttributionSourceState attributionSource) = 1 (sdk 35)
        let method = native_method(&reg, 35, "android.media.IMediaPlayerService", 1);
        assert_eq!(method.name, "create");
        // [int32 1 (presence)][int32 12 (size: 4+4+4)][int32 -1 (pid)][int32 1000 (uid)]
        let mut fields = Vec::new();
        fields.extend_from_slice(&(-1i32).to_le_bytes()); // pid
        fields.extend_from_slice(&1000i32.to_le_bytes()); // uid
        let buf = parcelable_buf(&fields);
        let nodes = decode_aidl_params(&reg, 35, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "attributionSource");
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "android.content.AttributionSourceState"
        ));
        assert!(nodes[0].children.len() >= 2);
        assert_eq!(nodes[0].children[0].name, "pid");
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(-1)));
        assert_eq!(nodes[0].children[1].name, "uid");
        assert!(matches!(
            nodes[0].children[1].value,
            DecodedValue::I64(1000)
        ));
    }

    #[test]
    fn decodes_native_imediaplayerservice_create_media_recorder_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_and_aosp_reg();
        // createMediaRecorder(in android.content.AttributionSourceState attributionSource) = 2 (sdk 35)
        let method = native_method(&reg, 35, "android.media.IMediaPlayerService", 2);
        assert_eq!(method.name, "createMediaRecorder");
        let mut fields = Vec::new();
        fields.extend_from_slice(&(-1i32).to_le_bytes()); // pid
        fields.extend_from_slice(&1000i32.to_le_bytes()); // uid
        let buf = parcelable_buf(&fields);
        let nodes = decode_aidl_params(&reg, 35, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "attributionSource");
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "android.content.AttributionSourceState"
        ));
        assert!(nodes[0].children.len() >= 2);
        assert_eq!(nodes[0].children[0].name, "pid");
        assert!(matches!(nodes[0].children[0].value, DecodedValue::I64(-1)));
        assert_eq!(nodes[0].children[1].name, "uid");
        assert!(matches!(
            nodes[0].children[1].value,
            DecodedValue::I64(1000)
        ));
    }

    // VolumeShaperConfiguration body (no presence flag — native C++ calls writeToParcel directly):
    //   [int32 size][int32 type=0 (ID)][int32 id][int32 optionFlags][double durationMs]
    //   [@nullable InterpolatorConfig presence=0 (null)]
    // size = 4 (size itself) + 4+4+4+8+4 = 28
    fn volume_shaper_config_buf(id: i32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&28i32.to_le_bytes()); // size header (incl. itself)
        b.extend_from_slice(&0i32.to_le_bytes()); // type = VolumeShaperConfigurationType.ID = 0
        b.extend_from_slice(&id.to_le_bytes()); // id
        b.extend_from_slice(&0i32.to_le_bytes()); // optionFlags
        b.extend_from_slice(&1.0f64.to_le_bytes()); // durationMs
        b.extend_from_slice(&0i32.to_le_bytes()); // @nullable InterpolatorConfig = null (presence 0)
        b
    }

    // VolumeShaperOperation body (no presence flag — native C++ calls writeToParcel directly):
    //   [int32 size][int32 flags][int32 replaceId][float xOffset]
    // size = 4 (size itself) + 4+4+4 = 16
    fn volume_shaper_op_buf(flags: i32, replace_id: i32, x_offset: f32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&16i32.to_le_bytes()); // size header (incl. itself)
        b.extend_from_slice(&flags.to_le_bytes()); // flags
        b.extend_from_slice(&replace_id.to_le_bytes()); // replaceId
        b.extend_from_slice(&x_offset.to_le_bytes()); // xOffset
        b
    }

    #[test]
    fn decodes_native_imediaplayer_apply_volume_shaper_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_and_aosp_reg();
        // applyVolumeShaper(in android.media.VolumeShaperConfiguration configuration,
        //   in android.media.VolumeShaperOperation operation) = 37 (sdk 35)
        // native C++ BpMediaPlayer calls config->writeToParcel (no presence flag).
        let method = native_method(&reg, 35, "android.media.IMediaPlayer", 37);
        assert_eq!(method.name, "applyVolumeShaper");
        let mut buf = volume_shaper_config_buf(42);
        buf.extend_from_slice(&volume_shaper_op_buf(2, -1, 0.0));
        let nodes = decode_aidl_params(&reg, 35, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "configuration");
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "android.media.VolumeShaperConfiguration"
        ));
        assert_eq!(nodes[1].name, "operation");
        assert!(matches!(
            &nodes[1].value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "android.media.VolumeShaperOperation"
        ));
    }

    #[test]
    fn decodes_native_imediaplayer_get_volume_shaper_state_request() {
        use crate::decode::{decode_aidl_params, DecodedValue};
        let reg = native_and_aosp_reg();
        // getVolumeShaperState(int id, out android.media.VolumeShaperState state) = 38 (sdk 35)
        // request: writeInt32(id); the out state param carries no request bytes.
        let method = native_method(&reg, 35, "android.media.IMediaPlayer", 38);
        assert_eq!(method.name, "getVolumeShaperState");
        let buf = 7i32.to_le_bytes().to_vec(); // id
        let nodes = decode_aidl_params(&reg, 35, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "id");
        assert!(matches!(nodes[0].value, DecodedValue::I64(7)));
    }

    #[test]
    fn decodes_native_imediaplayer_get_volume_shaper_state_reply() {
        use crate::decode::{decode_native_reply, DecodedValue};
        let reg = native_and_aosp_reg();
        // getVolumeShaperState reply: native C++ writes int32 1 (presence) then
        // state->writeToParcel (size header + fields). VolumeShaperState has
        // float volume and float xOffset.
        // size = 4 (size itself) + 4 (volume) + 4 (xOffset) = 12
        let method = native_method(&reg, 35, "android.media.IMediaPlayer", 38);
        assert_eq!(method.name, "getVolumeShaperState");
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes()); // presence flag (written by native before writeToParcel)
        buf.extend_from_slice(&12i32.to_le_bytes()); // size header (incl. itself)
        buf.extend_from_slice(&0.5f32.to_le_bytes()); // volume
        buf.extend_from_slice(&0.25f32.to_le_bytes()); // xOffset
        let nodes = decode_native_reply(&reg, 35, method, &buf, 0, &[]);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "state");
        assert!(matches!(
            &nodes[0].value,
            DecodedValue::Parcelable { fqn, null: false } if fqn == "android.media.VolumeShaperState"
        ));
        assert_eq!(nodes[0].children.len(), 2);
        assert_eq!(nodes[0].children[0].name, "volume");
        assert!(
            matches!(nodes[0].children[0].value, DecodedValue::F64(v) if (v - 0.5).abs() < 1e-5)
        );
        assert_eq!(nodes[0].children[1].name, "xOffset");
        assert!(
            matches!(nodes[0].children[1].value, DecodedValue::F64(v) if (v - 0.25).abs() < 1e-5)
        );
    }

    #[test]
    fn typedef_def_loads_from_overlay() {
        use crate::model::{Prim, TypeRef};
        let mut overlay = OverlayLayer {
            source_path: "x".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        overlay.typedefs.insert(
            "android.hardware.graphics.composer@2.4::Display".into(),
            TypeRef::Primitive(Prim::U64),
        );
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        let t = reg
            .typedef_def(34, "android.hardware.graphics.composer@2.4::Display")
            .expect("typedef must resolve");
        assert_eq!(t, TypeRef::Primitive(Prim::U64));
        assert!(reg.typedef_def(34, "android.hardware.Missing").is_none());
    }

    #[test]
    fn typedef_def_follows_chain() {
        use crate::model::{Prim, TypeRef};
        // AliasedDisplay -> Display -> uint64_t; typedef_def should return Primitive(U64)
        let mut overlay = OverlayLayer {
            source_path: "x".into(),
            interfaces: Default::default(),
            enums: Default::default(),
            parcelables: Default::default(),
            unions: Default::default(),
            typedefs: Default::default(),
        };
        overlay
            .typedefs
            .insert("a@1.0::Display".into(), TypeRef::Primitive(Prim::U64));
        overlay.typedefs.insert(
            "a@1.0::AliasedDisplay".into(),
            TypeRef::UserDefined("a@1.0::Display".into()),
        );
        let reg = Registry::from_parts(vec![overlay], None, HashMap::new());
        let t = reg.typedef_def(34, "a@1.0::AliasedDisplay").expect("chain");
        assert_eq!(t, TypeRef::Primitive(Prim::U64));
    }

    #[test]
    fn lazy_typedef_def_resolves_from_aosp_corpus() {
        // Display is `typedef uint64_t Display` in android.hardware.graphics.composer@2.1 types.hal.
        // A registry built with with_aosp_dir must load it on demand without any overlay.
        use crate::model::{Prim, TypeRef};
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let reg = Registry::with_aosp_dir(repo_root.join("data/aosp"));
        let t = reg
            .typedef_def(35, "android.hardware.graphics.composer@2.1::Display")
            .expect("Display typedef must resolve from AOSP corpus");
        assert_eq!(t, TypeRef::Primitive(Prim::U64));
        // second call must hit the cache and return the same result
        let t2 = reg
            .typedef_def(35, "android.hardware.graphics.composer@2.1::Display")
            .expect("cached hit");
        assert_eq!(t2, TypeRef::Primitive(Prim::U64));
        // non-typedef fqn in the same package returns None
        assert!(reg
            .typedef_def(35, "android.hardware.graphics.composer@2.1::IComposer")
            .is_none());
    }

    #[test]
    fn resolve_user_type_finds_cross_package_typedef() {
        // simulates resolving "Display" in the context of IComposerCallback@2.4:
        //   candidate_pkgs = ["android.hardware.graphics.composer@2.4",
        //                      "android.hardware.graphics.composer@2.1"]
        // "Display" lives in @2.1 types.hal as typedef uint64_t Display.
        use crate::model::{Prim, TypeRef};
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let reg = Registry::with_aosp_dir(repo_root.join("data/aosp"));
        let pkgs = vec![
            "android.hardware.graphics.composer@2.4".to_string(),
            "android.hardware.graphics.composer@2.1".to_string(),
        ];
        let resolved = reg
            .resolve_user_type(35, "Display", &pkgs)
            .expect("Display must resolve to u64 via @2.1");
        assert_eq!(resolved, TypeRef::Primitive(Prim::U64));
    }

    #[test]
    fn resolve_user_type_finds_same_package_typedef() {
        // VsyncPeriodNanos lives in composer@2.4 types.hal as typedef uint32_t VsyncPeriodNanos.
        // it is found on the first candidate (current package).
        use crate::model::{Prim, TypeRef};
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let reg = Registry::with_aosp_dir(repo_root.join("data/aosp"));
        let pkgs = vec![
            "android.hardware.graphics.composer@2.4".to_string(),
            "android.hardware.graphics.composer@2.1".to_string(),
        ];
        let resolved = reg
            .resolve_user_type(35, "VsyncPeriodNanos", &pkgs)
            .expect("VsyncPeriodNanos must resolve to u32 via @2.4");
        assert_eq!(resolved, TypeRef::Primitive(Prim::U32));
    }

    #[test]
    fn parse_hidl_records_imports_in_interface() {
        // an interface with import a.b@1.0::types records "a.b@1.0" in its imports.
        use crate::parser::hidl::parse_hidl;
        let src = "package x.y@2.0; import a.b@1.0::types; interface IFoo { void foo(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces.len(), 1);
        assert!(
            r.interfaces[0].imports.contains(&"a.b@1.0".to_string()),
            "expected imports to contain \"a.b@1.0\", got {:?}",
            r.interfaces[0].imports,
        );
    }
}

use crate::model::{EnumDef, Interface, Method, OverlayLayer, Parcelable, TypeRef, Union};
use std::collections::{HashMap, HashSet};
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
    /// HIDL typedef cache: (sdk, fqn) → raw typedef target (before chain-following).
    /// Absent means not yet looked up; Some(target) is the raw value from types.hal.
    lazy_typedef_cache: RwLock<HashMap<(u32, String), TypeRef>>,
    /// (sdk, pkg@ver) pairs whose types.hal has been scanned (or confirmed absent).
    /// Prevents re-parsing the same types.hal on every miss within the same package.
    types_hal_scanned: RwLock<HashSet<(u32, String)>>,
    /// (sdk, pkg@ver::IFaceName) pairs whose .hal interface file has been scanned for
    /// nested types (enums and structs declared inside the interface body).
    iface_hal_scanned: RwLock<HashSet<(u32, String)>>,
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
            lazy_typedef_cache: RwLock::new(HashMap::new()),
            types_hal_scanned: RwLock::new(HashSet::new()),
            iface_hal_scanned: RwLock::new(HashSet::new()),
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
                        let mut iface = parsed.interfaces.into_iter().find(|i| i.fqn == fqn)?;
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
            if fqn.contains('@') {
                // HIDL enum fqn — lazy_typed would look for .aidl files (wrong path).
                // ensure the right .hal is parsed, then read directly from the cache.
                if let Some((pkg_at_ver, type_part)) = fqn.split_once("::") {
                    if type_part.contains('.') {
                        // nested type: pkg@ver::Iface.TypeName — load the interface .hal
                        if let Some((iface_name, _)) = type_part.split_once('.') {
                            let iface_fqn = format!("{}::{}", pkg_at_ver, iface_name);
                            let needs_scan = !self
                                .iface_hal_scanned
                                .read()
                                .unwrap()
                                .contains(&(sdk, iface_fqn.clone()));
                            if needs_scan {
                                self.load_hidl_iface_hal(sdk, &iface_fqn);
                            }
                        }
                    } else {
                        // top-level enum in types.hal
                        let needs_scan = !self
                            .types_hal_scanned
                            .read()
                            .unwrap()
                            .contains(&(sdk, pkg_at_ver.to_string()));
                        if needs_scan {
                            self.load_hidl_types_hal(sdk, pkg_at_ver);
                        }
                    }
                }
                return self
                    .lazy_enum_cache
                    .read()
                    .unwrap()
                    .get(&(sdk, fqn.to_string()))
                    .copied()
                    .flatten();
            }
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
            // HIDL structs live in types.hal or nested inside interface .hal files,
            // not in .aidl files. For pkg@ver::Name fqns, ensure the right file is parsed.
            if fqn.contains('@') {
                if let Some((pkg_at_ver, type_part)) = fqn.split_once("::") {
                    if type_part.contains('.') {
                        // nested struct inside interface .hal — load the interface file
                        if let Some((iface_name, _)) = type_part.split_once('.') {
                            let iface_fqn = format!("{}::{}", pkg_at_ver, iface_name);
                            let needs_scan = !self
                                .iface_hal_scanned
                                .read()
                                .unwrap()
                                .contains(&(sdk, iface_fqn.clone()));
                            if needs_scan {
                                self.load_hidl_iface_hal(sdk, &iface_fqn);
                            }
                        }
                    } else {
                        // top-level struct in types.hal
                        let needs_scan = !self
                            .types_hal_scanned
                            .read()
                            .unwrap()
                            .contains(&(sdk, pkg_at_ver.to_string()));
                        if needs_scan {
                            self.load_hidl_types_hal(sdk, pkg_at_ver);
                        }
                    }
                }
                // return directly from cache; lazy_typed would try .aidl files (wrong)
                return self
                    .lazy_parcelable_cache
                    .read()
                    .unwrap()
                    .get(&(sdk, fqn.to_string()))
                    .copied()
                    .flatten();
            }
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

    /// Look up an interface by sdk + fqn. Checks overlays, then the lazy AOSP backend.
    /// Used for HIDL cross-package type resolution (getting an interface's imports list).
    pub fn iface_def(&self, sdk: u32, fqn: &str) -> Option<&'static Interface> {
        for overlay in self.overlays.iter().rev() {
            if overlay.interfaces.contains_key(fqn) {
                // overlays store Interface by value; can't return 'static from here.
                // for now, only lazy-cache lookup returns 'static; overlays won't
                // contain HIDL import metadata in practice (overlays are user files).
                break;
            }
        }
        if self.aosp_root.is_some() {
            return self.lazy_resolve_recursive(sdk, fqn);
        }
        None
    }

    /// Resolve a bare (unqualified) HIDL type name against an ordered list of
    /// candidate packages. `candidate_pkgs` should include the current package
    /// first, then any explicitly imported packages from the interface definition.
    /// Returns the resolved TypeRef: a primitive for typedefs, or a fully-qualified
    /// UserDefined fqn for enums and parcelables. Returns None if not found.
    pub fn resolve_user_type(
        &self,
        sdk: u32,
        name: &str,
        candidate_pkgs: &[String],
    ) -> Option<TypeRef> {
        for pkg in candidate_pkgs {
            let qualified = format!("{}::{}", pkg, name);
            // typedef chain: returns the terminal resolved type
            if let Some(ty) = self.typedef_def(sdk, &qualified) {
                return Some(ty);
            }
            // enum: return the qualified fqn for the caller to decode with
            if self.enum_def(sdk, &qualified).is_some() {
                return Some(TypeRef::UserDefined(qualified));
            }
            // parcelable/struct: same
            if self.parcelable_def(sdk, &qualified).is_some() {
                return Some(TypeRef::UserDefined(qualified));
            }
        }
        None
    }

    /// Resolve a HIDL primitive typedef by fqn. Follows typedef chains (a typedef
    /// of a typedef) up to 8 levels deep to guard against cycles. Returns the
    /// terminal TypeRef — either a primitive/string/list or a UserDefined fqn
    /// that is an enum or parcelable (not another typedef). Returns None if `fqn`
    /// is not a typedef in any overlay or in the AOSP corpus types.hal.
    pub fn typedef_def(&self, sdk: u32, fqn: &str) -> Option<TypeRef> {
        self.typedef_def_depth(sdk, fqn, 0)
    }

    fn typedef_def_depth(&self, sdk: u32, fqn: &str, depth: u32) -> Option<TypeRef> {
        if depth > 8 {
            return None; // cycle or very deep chain — give up
        }
        for overlay in self.overlays.iter().rev() {
            if let Some(target) = overlay.typedefs.get(fqn) {
                // if target is itself a UserDefined, it might be another typedef; follow it
                if let TypeRef::UserDefined(inner_fqn) = target {
                    if let Some(resolved) = self.typedef_def_depth(sdk, inner_fqn, depth + 1) {
                        return Some(resolved);
                    }
                }
                return Some(target.clone());
            }
        }

        // lazy HIDL types.hal lookup — only for pkg@ver::Name-shaped fqns
        if self.aosp_root.is_some() {
            if let Some((pkg_at_ver, _)) = fqn.split_once("::") {
                let pkg_at_ver = pkg_at_ver.to_string();
                let already_scanned = self
                    .types_hal_scanned
                    .read()
                    .unwrap()
                    .contains(&(sdk, pkg_at_ver.clone()));
                if !already_scanned {
                    self.load_hidl_types_hal(sdk, &pkg_at_ver);
                }
                let cached = self
                    .lazy_typedef_cache
                    .read()
                    .unwrap()
                    .get(&(sdk, fqn.to_string()))
                    .cloned();
                if let Some(target) = cached {
                    if let TypeRef::UserDefined(inner_fqn) = &target {
                        if let Some(resolved) = self.typedef_def_depth(sdk, inner_fqn, depth + 1) {
                            return Some(resolved);
                        }
                    }
                    return Some(target);
                }
            }
        }

        None
    }

    // load typedefs and parcelables (structs) from `pkg_at_ver`'s types.hal.
    // locates the file by finding any already-indexed interface in the same package and
    // looking for types.hal alongside it. marks the package scanned regardless of outcome.
    fn load_hidl_types_hal(&self, sdk: u32, pkg_at_ver: &str) {
        self.populate_fqn_index(sdk);
        let prefix = format!("{}::", pkg_at_ver);
        let types_hal_path: Option<PathBuf> = {
            let idx = self.fqn_index.read().unwrap();
            idx.get(&sdk).and_then(|m| {
                m.iter()
                    .find(|(k, _)| k.starts_with(&prefix))
                    .and_then(|(_, p)| p.parent().map(|d| d.join("types.hal")))
            })
        };
        if let Some(path) = types_hal_path {
            if let Ok(src) = std::fs::read_to_string(&path) {
                match crate::parser::hidl::parse_hidl(&src) {
                    Ok(parsed) => {
                        {
                            let mut cache = self.lazy_typedef_cache.write().unwrap();
                            for (fqn, target) in parsed.typedefs {
                                cache.entry((sdk, fqn)).or_insert(target);
                            }
                        }
                        // also cache parcelables (top-level structs in types.hal)
                        {
                            let mut pcache = self.lazy_parcelable_cache.write().unwrap();
                            for p in parsed.parcelables {
                                let key = (sdk, p.fqn.clone());
                                pcache
                                    .entry(key)
                                    .or_insert_with(|| Some(Box::leak(Box::new(p))));
                            }
                        }
                        // also cache enums (top-level enums in types.hal)
                        {
                            let mut ecache = self.lazy_enum_cache.write().unwrap();
                            for e in parsed.enums {
                                let key = (sdk, e.fqn.clone());
                                ecache
                                    .entry(key)
                                    .or_insert_with(|| Some(Box::leak(Box::new(e))));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("binderdump-hidl: failed to parse {}: {}", path.display(), e);
                    }
                }
            }
        }
        self.types_hal_scanned
            .write()
            .unwrap()
            .insert((sdk, pkg_at_ver.to_string()));
    }

    /// Parse an interface's .hal file and cache any nested enum/parcelable types it declares.
    /// `iface_fqn` is a fully-qualified HIDL interface fqn like `pkg@ver::IFaceName`. The
    /// fqn_index is used to locate the .hal file; both enum and parcelable caches are
    /// populated from the parsed result. Marks `iface_fqn` in `iface_hal_scanned` even on
    /// failure so we don't re-attempt on every miss.
    fn load_hidl_iface_hal(&self, sdk: u32, iface_fqn: &str) {
        self.populate_fqn_index(sdk);
        let hal_path: Option<PathBuf> = {
            let idx = self.fqn_index.read().unwrap();
            idx.get(&sdk).and_then(|m| m.get(iface_fqn).cloned())
        };
        if let Some(path) = hal_path {
            if let Ok(src) = std::fs::read_to_string(&path) {
                match crate::parser::hidl::parse_hidl(&src) {
                    Ok(parsed) => {
                        {
                            let mut ecache = self.lazy_enum_cache.write().unwrap();
                            for e in parsed.enums {
                                let key = (sdk, e.fqn.clone());
                                ecache
                                    .entry(key)
                                    .or_insert_with(|| Some(Box::leak(Box::new(e))));
                            }
                        }
                        {
                            let mut pcache = self.lazy_parcelable_cache.write().unwrap();
                            for p in parsed.parcelables {
                                let key = (sdk, p.fqn.clone());
                                pcache
                                    .entry(key)
                                    .or_insert_with(|| Some(Box::leak(Box::new(p))));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("binderdump-hidl: failed to parse {}: {}", path.display(), e);
                    }
                }
            }
        }
        self.iface_hal_scanned
            .write()
            .unwrap()
            .insert((sdk, iface_fqn.to_string()));
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
        let mut hidl_pending: Vec<(
            PathBuf,
            Vec<Interface>,
            Vec<(String, TypeRef)>,
            Vec<EnumDef>,
            Vec<Parcelable>,
        )> = Vec::new();
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
                            // AIDL files have no HIDL typedef declarations
                            typedefs: Default::default(),
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
                            v.interfaces.len(),
                            path.display()
                        );
                        hidl_pending.push((path, v.interfaces, v.typedefs, v.enums, v.parcelables));
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
            let all: Vec<Interface> = hidl_pending
                .iter()
                .flat_map(|(_, v, _, _, _)| v.clone())
                .collect();
            match crate::parser::hidl::resolve_inheritance(all) {
                Ok(resolved) => {
                    let by_fqn: HashMap<String, Interface> =
                        resolved.into_iter().map(|i| (i.fqn.clone(), i)).collect();
                    for (path, parsed, file_typedefs, file_enums, file_parcelables) in hidl_pending
                    {
                        let mut interfaces = HashMap::new();
                        for iface in parsed {
                            if let Some(r) = by_fqn.get(&iface.fqn) {
                                interfaces.insert(iface.fqn, r.clone());
                            }
                        }
                        layers.push(OverlayLayer {
                            source_path: path,
                            interfaces,
                            enums: file_enums.into_iter().map(|e| (e.fqn.clone(), e)).collect(),
                            parcelables: file_parcelables
                                .into_iter()
                                .map(|p| (p.fqn.clone(), p))
                                .collect(),
                            unions: Default::default(),
                            typedefs: file_typedefs.into_iter().collect(),
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

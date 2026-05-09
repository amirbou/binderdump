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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_recognized() {
        assert_eq!(lookup_special(0x5f504e47), Some(SpecialTxn::Ping));
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
        };
        overlay
            .interfaces
            .insert("a.b.IFoo".into(), iface("a.b.IFoo", &["start", "stop"]));
        let reg = Registry::from_parts(vec![overlay], None);
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
        };
        // Even if an overlay declared a method at PING's value, special table wins.
        overlay
            .interfaces
            .insert("a.b.IFoo".into(), iface("a.b.IFoo", &[]));
        let reg = Registry::from_parts(vec![overlay], None);
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
        };
        overlay
            .interfaces
            .insert("a.b.IFoo".into(), iface("a.b.IFoo", &["only"]));
        let reg = Registry::from_parts(vec![overlay], None);
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
}

use crate::model::{Interface, Method, OverlayLayer};
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
}

pub struct Registry {
    overlays: Vec<OverlayLayer>,
    aosp_root: Option<PathBuf>,
    /// Cache for lazy loads. `None` value caches negative lookups so we
    /// don't re-stat / re-parse missing files. Box::leak'd so the
    /// `&'static Interface` borrow can outlive the RwLockReadGuard at
    /// resolve time.
    lazy_cache: RwLock<HashMap<(u32, String), Option<&'static Interface>>>,
    /// fqn → file-path index, populated lazily once per SDK on first
    /// indirect lookup. The Option means we've populated for that SDK
    /// already (Some) or not yet (absent).
    fqn_index: RwLock<HashMap<u32, HashMap<String, PathBuf>>>,
}

impl Registry {
    pub fn empty() -> Self {
        Self::from_parts(vec![], None)
    }

    pub fn from_parts(overlays: Vec<OverlayLayer>, aosp_root: Option<PathBuf>) -> Self {
        Self {
            overlays,
            aosp_root,
            lazy_cache: RwLock::new(HashMap::new()),
            fqn_index: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_aosp_dir(root: PathBuf) -> Self {
        Self::from_parts(vec![], Some(root))
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

        // fall through to lazy backend, if any
        if self.aosp_root.is_some() {
            let leaked = self.lazy_resolve_recursive(android_sdk, fqn);
            return self.materialize_lazy(leaked, code);
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
                    Ok(parsed) => parsed.into_iter().find(|i| i.fqn == fqn),
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
                    Ok(v) => {
                        eprintln!(
                            "binderdump-aidl: loaded {} interface(s) from {}",
                            v.len(),
                            path.display()
                        );
                        layers.push(OverlayLayer {
                            source_path: path,
                            interfaces: v.into_iter().map(|i| (i.fqn.clone(), i)).collect(),
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

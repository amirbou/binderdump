// build script: walks data/aosp/android-<sdk>/{aidl,hal} and emits a single
// `aosp_generated.rs` whose body is a sequence of `acc.add(sdk, fqn, iface)`
// statements. registry.rs `include!`s it inside `with_builtin()`.

#[path = "src/model.rs"]
mod model;
#[path = "src/parser/aidl.rs"]
mod parser_aidl;
#[path = "src/parser/hidl.rs"]
mod parser_hidl;

use model::{Flavor, Interface};
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=data/aosp");
    println!("cargo:rerun-if-changed=src/parser/aidl.rs");
    println!("cargo:rerun-if-changed=src/parser/hidl.rs");
    println!("cargo:rerun-if-changed=src/model.rs");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join("aosp_generated.rs");
    let mut out = std::fs::File::create(&out_path).expect("open out file");

    writeln!(out, "{{").unwrap();

    write_body(&mut out);

    // Emit a unit expression as the last statement of the block.
    writeln!(out, "    ()").unwrap();
    writeln!(out, "}}").unwrap();
}

fn write_body(out: &mut std::fs::File) {
    let data_root = Path::new("data/aosp");
    if !data_root.exists() {
        // Empty stub for users who haven't dropped AOSP files yet.
        writeln!(
            out,
            "    // data/aosp/ does not exist; built-in tables are empty."
        )
        .unwrap();
        return;
    }

    for version_entry in std::fs::read_dir(data_root)
        .expect("read data/aosp")
        .flatten()
    {
        let version_dir = version_entry.path();
        if !version_dir.is_dir() {
            continue;
        }
        let version_str = version_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        // Directory name "android-34" -> sdk = 34.
        let sdk: u32 = version_str
            .strip_prefix("android-")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("expected dir like 'android-34', got '{}'", version_str));

        emit_aidl_for_version(out, sdk, &version_dir);
        emit_hidl_for_version(out, sdk, &version_dir);
    }
}

fn emit_aidl_for_version(out: &mut std::fs::File, sdk: u32, version_dir: &Path) {
    let dir = version_dir.join("aidl");
    if !dir.exists() {
        return;
    }
    for path in walk_files_with_ext(&dir, "aidl") {
        let src = std::fs::read_to_string(&path).expect("read source");
        let parsed = parser_aidl::parse_aidl(&src)
            .unwrap_or_else(|e| panic!("failed to parse {}: {:?}", path.display(), e));
        for iface in &parsed {
            emit_iface(out, sdk, iface);
        }
    }
}

fn emit_hidl_for_version(out: &mut std::fs::File, sdk: u32, version_dir: &Path) {
    let dir = version_dir.join("hal");
    if !dir.exists() {
        return;
    }
    // HIDL `extends` can cross files. Parse every .hal first, then resolve
    // inheritance once across the whole set so unknown parents become a
    // hard error per parser_hidl::resolve_inheritance.
    let mut all: Vec<Interface> = Vec::new();
    for path in walk_files_with_ext(&dir, "hal") {
        let src = std::fs::read_to_string(&path).expect("read source");
        let parsed = parser_hidl::parse_hidl(&src)
            .unwrap_or_else(|e| panic!("failed to parse {}: {:?}", path.display(), e));
        all.extend(parsed);
    }
    let resolved = parser_hidl::resolve_inheritance(all)
        .unwrap_or_else(|e| panic!("hidl inheritance for android-{}: {}", sdk, e));
    for iface in &resolved {
        emit_iface(out, sdk, iface);
    }
}

fn walk_files_with_ext(dir: &Path, ext: &str) -> Vec<std::path::PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some(ext))
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn emit_iface(out: &mut std::fs::File, sdk: u32, iface: &Interface) {
    writeln!(
        out,
        "    acc.add({}, {:?}, crate::model::Interface {{",
        sdk, iface.fqn
    )
    .unwrap();
    writeln!(out, "        fqn: {:?}.to_string(),", iface.fqn).unwrap();
    writeln!(out, "        flavor: {},", flavor_lit(iface.flavor)).unwrap();
    writeln!(out, "        base_code: {},", iface.base_code).unwrap();
    writeln!(out, "        methods: vec![").unwrap();
    for m in &iface.methods {
        writeln!(out, "            crate::model::Method {{").unwrap();
        writeln!(out, "                name: {:?}.to_string(),", m.name).unwrap();
        writeln!(out, "                params: vec![],").unwrap();
        writeln!(out, "                return_type: None,").unwrap();
        writeln!(out, "                oneway: {},", m.oneway).unwrap();
        writeln!(out, "            }},").unwrap();
    }
    writeln!(out, "        ],").unwrap();
    writeln!(
        out,
        "        extends: {:?}.map(|s: &str| s.to_string()),",
        iface.extends.as_deref()
    )
    .unwrap();
    writeln!(out, "    }});").unwrap();
}

fn flavor_lit(f: Flavor) -> &'static str {
    match f {
        Flavor::Aidl => "crate::model::Flavor::Aidl",
        Flavor::Hidl => "crate::model::Flavor::Hidl",
    }
}

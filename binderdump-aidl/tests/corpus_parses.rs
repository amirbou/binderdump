// Walks the committed AOSP corpus and asserts every .aidl / .hal file
// parses cleanly. Regression test for the parser fixes that landed
// alongside the corpus sync.
//
// If the corpus dir is absent (e.g. shallow checkout that skipped LFS,
// or someone deleted data/aosp/), the test trivially passes.

use std::collections::BTreeMap;
use std::path::PathBuf;

use binderdump_aidl::parser::{aidl, hidl};

#[test]
fn aosp_corpus_parses_with_no_failures() {
    let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/aosp");
    if !root.exists() {
        // corpus dir absent — nothing to validate, trivially pass.
        return;
    }

    let mut aidl_ok = 0usize;
    let mut hal_ok = 0usize;
    let mut aidl_err: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut hal_err: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for entry in walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        let rel = path
            .strip_prefix(&root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string());
        match ext {
            "aidl" => match aidl::parse_aidl(&src) {
                Ok(_) => aidl_ok += 1,
                Err(e) => {
                    let reason = e
                        .first()
                        .map(|s| format!("{:?}", s.reason()))
                        .unwrap_or_else(|| "unknown".into());
                    aidl_err.entry(reason).or_default().push(rel);
                }
            },
            "hal" => match hidl::parse_hidl(&src) {
                Ok(_) => hal_ok += 1,
                Err(e) => hal_err.entry(e).or_default().push(rel),
            },
            _ => {}
        }
    }

    let aidl_fail: usize = aidl_err.values().map(|v| v.len()).sum();
    let hal_fail: usize = hal_err.values().map(|v| v.len()).sum();

    if aidl_fail == 0 && hal_fail == 0 {
        eprintln!("AOSP corpus: AIDL {} OK, HAL {} OK", aidl_ok, hal_ok);
        return;
    }

    // build a digestible failure summary
    let mut msg = format!(
        "AOSP corpus parse failures: AIDL {} / {} failed, HAL {} / {} failed",
        aidl_fail,
        aidl_ok + aidl_fail,
        hal_fail,
        hal_ok + hal_fail
    );
    for (reason, files) in &aidl_err {
        msg.push_str(&format!("\n  AIDL  {:>4}  {}", files.len(), reason));
        for f in files.iter().take(3) {
            msg.push_str(&format!("\n          - {}", f));
        }
    }
    for (reason, files) in &hal_err {
        msg.push_str(&format!("\n  HAL   {:>4}  {}", files.len(), reason));
        for f in files.iter().take(3) {
            msg.push_str(&format!("\n          - {}", f));
        }
    }
    panic!("{}", msg);
}

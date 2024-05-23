use std::{env, fs, path};
use libbpf_cargo::SkeletonBuilder;

const BPF_PROGRAMS_DIR: &str = "src/bpf";

fn bind_binder() {
    let bindings = bindgen::Builder::default()
        .header("binder_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate bindings for <linux/android/binder.h>");

    let out_path = path::PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("binder_gen.rs"))
        .expect("failed to write bindings for <linux/android/binder.h> to `binder_gen.rs`");
}

fn build_bpf_program(path: &path::Path, out_dir: &path::Path) {
    println!("building bpf program: {}", path.display());

    let mut out = out_dir.join(path.file_stem().unwrap());
    out.set_extension("skel.rs");

    SkeletonBuilder::new()
        .source(path)
        .build_and_generate(&out).unwrap();
}

fn build_bpf() {
    let out_dir = path::PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let paths = fs::read_dir(BPF_PROGRAMS_DIR).expect("failed to ls bpf programs directory");
    for path in paths {
        let path = path.unwrap().path();
        if path.file_name().is_some_and(|filename| filename.to_string_lossy().ends_with(".bpf.c")) {
            build_bpf_program(&path, &out_dir);
        }
    }
    println!("cargo::rerun-if-changed={}", BPF_PROGRAMS_DIR);
}

fn main() {
    bind_binder();
    build_bpf();
}

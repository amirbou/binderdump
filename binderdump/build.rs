use libbpf_cargo::SkeletonBuilder;
use std::{env, fs, path};

const BPF_PROGRAMS_DIR: &str = "src/bpf";

fn bindgen_generate(src: &path::Path, dst: &path::Path) {
    let bindings = bindgen::Builder::default()
        .header(src.to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect(&format!(
            "failed to generate bindings for {}",
            src.display()
        ));

    let out_path = path::PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join(dst)).expect(&format!(
        "failed to write bindings for {} to {}",
        src.display(),
        dst.display()
    ));
}

fn bind_common_types() {
    let src = path::PathBuf::from("src/bpf/common_types.h");
    let dst = path::PathBuf::from("common_types.rs");
    bindgen_generate(&src, &dst);
}

fn build_bpf_program(path: &path::Path, out_dir: &path::Path) {
    println!("building bpf program: {}", path.display());

    let mut out = out_dir.join(path.file_stem().unwrap());
    out.set_extension("skel.rs");

    SkeletonBuilder::new()
        .source(path)
        .clang_args(["-std=gnu11"])
        .build_and_generate(&out)
        .unwrap();
}

fn build_bpf() {
    let out_dir = path::PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let paths = fs::read_dir(BPF_PROGRAMS_DIR).expect("failed to ls bpf programs directory");
    for path in paths {
        let path = path.unwrap().path();
        if path
            .file_name()
            .is_some_and(|filename| filename.to_string_lossy().ends_with(".bpf.c"))
        {
            build_bpf_program(&path, &out_dir);
        }
    }
    println!("cargo::rerun-if-changed={}", BPF_PROGRAMS_DIR);
}

fn main() {
    bind_common_types();
    build_bpf();
}

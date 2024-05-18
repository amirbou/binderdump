use std::{env, fs, path};
use libbpf_cargo::SkeletonBuilder;

const BPF_PROGRAMS_DIR: &str = "src/bpf";
const BPF_SKEL_DIR: &str = "src/bpf-skel";


fn build_bpf_program(path: &path::Path, out_dir: &path::Path) {
    println!("building bpf program: {}", path.display());

    let mut out = out_dir.join(path.file_stem().unwrap());
    out.set_extension("skel.rs");

    SkeletonBuilder::new()
        .source(path)
        .build_and_generate(&out).unwrap();
}

fn build_bpf() {
    let manifset = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR environment variable must be set");
    let out_dir = path::PathBuf::from(manifset).join(BPF_SKEL_DIR);

    fs::create_dir_all(&out_dir).unwrap();

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
    build_bpf();
}

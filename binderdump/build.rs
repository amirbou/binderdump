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

fn build_bpf_program(
    path: &path::Path,
    out_dir: &path::Path,
    is_transaction_stack_feature_enabled: bool,
) {
    println!("building bpf program: {}", path.display());

    let mut out = out_dir.join(path.file_stem().unwrap());
    out.set_extension("skel.rs");

    let target = env::var("TARGET").unwrap().replace('-', "_");
    let cc_env_var = String::from("CC_") + &target;
    // Use the same compiler for the BPF as the rest of the program
    let clang =
        env::var(&cc_env_var).expect(&format!("No {} environment variable found", &cc_env_var));

    // And the same sysroot (a little hacky)
    let sysroot = env::var(&(String::from("BINDGEN_EXTRA_CLANG_ARGS_") + &target)).ok();
    let mut clang_args = vec![String::from("-std=gnu11")];
    if let Some(sysroot_arg) = sysroot {
        let target_include_arg = format!(
            "-I{}/usr/include/{}",
            &sysroot_arg.strip_prefix("--sysroot=").unwrap(),
            env::var("TARGET").unwrap()
        );
        clang_args.push(sysroot_arg);
        clang_args.push(target_include_arg);
    }

    // Add architecture define (i.e __aarch64__) so the correct headers are used for arch dependant structs (pt_regs)
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    clang_args.push(format!("-D__{}__", arch));

    if is_transaction_stack_feature_enabled {
        clang_args.push(String::from("-DFEATURE_TRANSACTION_STACK"));
    }

    SkeletonBuilder::new()
        .source(path)
        .clang_args(clang_args)
        .clang(clang)
        .build_and_generate(&out)
        .unwrap();
}

fn build_bpf(is_transaction_stack_feature_enabled: bool) {
    let out_dir = path::PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let paths = fs::read_dir(BPF_PROGRAMS_DIR).expect("failed to ls bpf programs directory");
    for path in paths {
        let path = path.unwrap().path();
        if path
            .file_name()
            .is_some_and(|filename| filename.to_string_lossy().ends_with(".bpf.c"))
        {
            build_bpf_program(&path, &out_dir, is_transaction_stack_feature_enabled);
        }
    }
    println!("cargo::rerun-if-changed={}", BPF_PROGRAMS_DIR);
}

fn main() {
    let is_transaction_stack_feature_enabled = cfg!(feature = "transaction-stack");
    bind_common_types();
    build_bpf(is_transaction_stack_feature_enabled);
}

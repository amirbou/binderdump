use std::{env, fs, path};
use autotools;
use copy_dir::copy_dir;

const ELFUTILS_DIR: &str = "aosp-elfutils";
const ELFUTILS_PATCHES_DIR: &str = "aosp-elfutils-patches";

fn num_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |count| count.get())
}

fn apply_patch(patch_file: &path::Path, src_dir: &path::Path) {
    println!("applying patch file {} to directory {}", patch_file.display(), src_dir.display());
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("patch -p1 <{}", patch_file.display()))
        .current_dir(src_dir)
        .status().expect("failed to apply patch");

    assert!(status.success(), "failed to apply patch");
}

fn apply_patches(patch_dir: &path::Path, src_dir: &path::Path) {
    let paths = fs::read_dir(patch_dir).expect("failed to ls patch directory");
    for path in paths {
        let path = path.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "patch") {
            apply_patch(&path, src_dir);
        }
    }
}

fn make_elfutils(build_dir: &path::Path, out_dir: &path::Path) -> String {
    println!("Building elfutils");
    // elfutils is annoying, it doesn't allow building only the required libelf,
    // so some patching is needed.
    // It seems that copying the sources to the OUT_DIR and building there is the best way to do that as:
    // 1. patches can be applied without modifiying the tree
    // 2. autoreconf won't change the mtime of files in the src directory, causing an unnecessary rebuild 
    let src_dir = out_dir.join(ELFUTILS_DIR);
    let patch_dir = build_dir.join(ELFUTILS_PATCHES_DIR);
    
    // If cargo decided to run us again, be on the safe side and recompile the source from scrach
    // best effort to remove the srcs, they will not exists after a `cargo clean`.  
    fs::remove_dir_all(&src_dir).ok();
    copy_dir(&build_dir.join(ELFUTILS_DIR), &src_dir).expect("failed to copy elfutils sources to the build dir");
    apply_patches(&patch_dir, &src_dir);

    println!("HOST: {}", std::env::var("HOST").unwrap());
    let host = std::env::var("HOST").ok();

    let dst = autotools::Config::new(&src_dir)
        .reconf("-i")
        .enable("maintainer-mode", None)
        .disable("debuginfod", None)
        .disable("libdebuginfod", None)
        .without("lzma", None)
        .without("bzlib", None)
        .without("zstd", None)
        .cflag(format!("-I{}", src_dir.join("bionic-fixup/").display()))
        .cflag(format!("-include {}", src_dir.join("bionic-fixup/AndroidFixup.h").display()))
        .cflag(format!("-include {}", patch_dir.join("patch.h").display()))
        .cflag("-D_FILE_OFFSET_BITS=64")
        .fast_build(true)
        .config_option("host", host.as_deref())
        .insource(true)
        .build();

    println!("cargo::rustc-link-lib=libelf");
    format!("-I{}", dst.join("include").display())
}

fn make_libbpf(src_dir: &path::Path, cflags: &str) {
    let out_dir = path::PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let obj_dir = out_dir.join("obj");
    
    std::fs::create_dir_all(&obj_dir).unwrap();

    let compiler = cc::Build::new().try_get_compiler().expect(
        "a C compiler is required to compile libbpf using the vendored copy of libbpf",
    );

    let cflags = format!(
        "{} -include {}",
        cflags,
        compiler
            .path()
            .parent()
            .unwrap()
            .join("../sysroot/usr/include/linux/types.h")
            .display()
    );

    let status = std::process::Command::new("make")
        .arg("install")
        .arg("-j")
        .arg(&format!("{}", num_cpus()))
        .env("BUILD_STATIC_ONLY", "y")
        .env("PREFIX", "/")
        .env("OBJDIR", &obj_dir)
        .env("DESTDIR", &out_dir)
        .env("CC", &compiler.path())
        .env("CFLAGS", cflags)
        .current_dir(&src_dir.join("libbpf/src"))
        .status()
        .expect("failed to make libbpf");

    assert!(status.success(), "failed to make libbpf");
    println!("cargo::rustc-link-lib=libbpf");
}


fn android_patches() {
    let src_dir = path::PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = path::PathBuf::from(env::var_os("OUT_DIR").unwrap());

    
    let cflags_elfutils = make_elfutils(&src_dir, &out_dir);
    make_libbpf(&src_dir, &cflags_elfutils);
    println!(
        "cargo::rustc-link-search=native={}",
        out_dir.display()
    );


    println!("cargo::rerun-if-changed={}", src_dir.join(ELFUTILS_DIR).display());
    println!("cargo::rerun-if-changed={}", src_dir.join(ELFUTILS_PATCHES_DIR).display());
    println!("cargo::rerun-if-changed={}", src_dir.join("libbpf").display());
}

fn main() {
    // when not targeting android we rely on the `vendored` feature of libbpf-rs instead of compiling ourselves 
    if cfg!(target_os = "android") {
        android_patches();
    }
}

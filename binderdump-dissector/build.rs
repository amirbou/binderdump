use pkg_config;
use std::{env, path};

fn bindgen_generate(builder: bindgen::Builder, src: &path::Path, dst: &path::Path) {
    let bindings = builder
        .header(src.to_str().unwrap())
        .clang_arg("-fvisibility=hidden") // we want only functions annotated by WS_DLL_PUBLIC, which sets __attribute__((visibility("default"))), so turn everything else to hidden
        .rustified_enum("ftenum")
        .rustified_enum("field_display_e")
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

fn bind_wireshark(builder: bindgen::Builder) {
    let src = path::PathBuf::from("src/wireshark_wrapper.h");
    let dst = path::PathBuf::from("wireshark_gen.rs");
    bindgen_generate(builder, &src, &dst);
}

fn include_lib(
    mut builder: bindgen::Builder,
    lib_name: &str,
    install_pkg: &str,
) -> bindgen::Builder {
    let lib = pkg_config::probe_library(lib_name).expect(&format!(
        "Couldn't find {} library please install it (try `sudo apt install {}`)",
        lib_name, install_pkg
    ));
    for path in lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.to_string_lossy()))
    }
    builder
}

fn main() {
    let mut builder = bindgen::Builder::default();
    builder = include_lib(builder, "wireshark", "libwireshark-dev");
    builder = include_lib(builder, "glib-2.0", "libglib2.0-dev");
    bind_wireshark(builder);
}

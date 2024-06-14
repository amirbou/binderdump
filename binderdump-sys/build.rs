use std::{env, path};

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

fn bind_binder() {
    let src = path::PathBuf::from("src/binder_wrapper.h");
    let dst = path::PathBuf::from("binder_gen.rs");
    bindgen_generate(&src, &dst);
}

fn main() {
    bind_binder();
}

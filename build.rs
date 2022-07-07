// This file is based off the bindgen reference at https://rust-lang.github.io/rust-bindgen/tutorial-3.html

extern crate bindgen;

use std::path::PathBuf;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    let src = [
        "libraries/phc-winner-argon2/src/argon2.c",
        "libraries/phc-winner-argon2/src/core.c",
        "libraries/phc-winner-argon2/src/blake2/blake2b.c",
        "libraries/phc-winner-argon2/src/thread.c",
        "libraries/phc-winner-argon2/src/encoding.c",
        "libraries/phc-winner-argon2/src/opt.c",
    ];

    let mut builder = cc::Build::new();

    let build = builder
        .static_flag(true)
        .files(src.iter())
        .include("libraries/phc-winner-argon2/include")
        .flag("-std=c89")
        .flag("-pthread");
    
    build.compile("argon2");

    // println!("cargo:rustc-link-search={}", out_dir);
    // println!("cargo:rustc-link-lib=static=argon2");
    println!("cargo:rerun-if-changed=libraries/argon2_bindings.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("libraries/argon2_bindings.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings for argon2 library");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let bindings_out_path = PathBuf::from(format!("{}/argon2_bindings.rs", out_dir));

    bindings
        .write_to_file(bindings_out_path)
        .expect("Couldn't write argon2 library bindings");
}

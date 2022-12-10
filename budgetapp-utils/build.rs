fn main() {
    let supports_simd = cfg!(target_arch = "x86_64");

    let simd_src_file = if supports_simd {
        "libraries/phc-winner-argon2/src/opt.c"
    } else {
        "libraries/phc-winner-argon2/src/ref.c"
    };

    let src = [
        "libraries/phc-winner-argon2/src/argon2.c",
        "libraries/phc-winner-argon2/src/core.c",
        "libraries/phc-winner-argon2/src/blake2/blake2b.c",
        "libraries/phc-winner-argon2/src/thread.c",
        "libraries/phc-winner-argon2/src/encoding.c",
        simd_src_file,
    ];

    let mut builder = cc::Build::new();

    let build = builder
        .static_flag(true)
        .files(src.iter())
        .include("libraries/phc-winner-argon2/include")
        .warnings(false)
        .flag("-std=c89")
        .flag("-pthread");

    if supports_simd {
        build.flag_if_supported("-march=native");
    }

    build.compile("argon2");

    println!("cargo:rerun-if-changed=libraries/argon2_bindings.h");

    bindgen::Builder::default()
        .header("libraries/argon2_bindings.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings for argon2 library");
}

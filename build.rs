#[cfg(not(feature = "builtin"))]
use cmake::Config;
use std::env;

#[cfg(not(feature = "builtin"))]
fn main() {
    let dst = Config::new("./").define("MBEDTLS_USE_STATIC_LIBS", "ON")
    .define("BUILD_SHARED_LIBS", "OFF").build();

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-search=native={}", "/home/linuxbrew/.linuxbrew/lib");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedcrypto");

    bindgen::Builder::default()
        .headers(["crypto/test.h", "crypto/bip39.h"])
        .use_core()
        .derive_debug(true)
        .wrap_unsafe_ops(true)
        .generate_comments(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(env::var("OUT_DIR").unwrap() + "/bindings.rs")
        .unwrap();
}

#[cfg(feature = "builtin")]
fn main() {}

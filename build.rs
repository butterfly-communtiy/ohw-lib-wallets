#[cfg(feature = "build")]
use cmake::Config;
#[cfg(feature = "build")]
use std::time::SystemTime;

#[cfg(feature = "build")]
fn main() {
    println!("cargo:rerun-if-changed={:?}", SystemTime::now());

    let dst = Config::new("./")
        .define("MBEDTLS_USE_STATIC_LIBS", "ON")
        .define("BUILD_SHARED_LIBS", "OFF")
        .build();

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!(
        "cargo:rustc-link-search=native={}",
        "/home/linuxbrew/.linuxbrew/lib"
    );
    println!("cargo:rustc-link-search=native=/usr/local/lib/");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    println!("cargo:rustc-link-lib=static=mbedx509");

    bindgen::Builder::default()
        .headers(["psa/wrapper.h"])
        .use_core()
        .derive_debug(true)
        .generate_comments(true)
        .generate()
        .unwrap()
        .write_to_file("src/alg/bindings.rs")
        .unwrap();
}

#[cfg(not(feature = "build"))]
fn main() {}

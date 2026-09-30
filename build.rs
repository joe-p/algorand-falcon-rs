use std::path::Path;

// C sources needed for FALCON-DET1024. deterministic512.c is omitted since only
// the det1024 API is bound.
const SOURCES: &[&str] = &[
    "codec.c",
    "common.c",
    "deterministic1024.c",
    "falcon.c",
    "fft.c",
    "fpr.c",
    "keygen.c",
    "rng.c",
    "shake.c",
    "sign.c",
    "vrfy.c",
];

fn main() {
    let dir = Path::new("falcon");
    if !dir.join("falcon.h").exists() {
        panic!("falcon C sources not found; run `git submodule update --init`");
    }

    let mut build = cc::Build::new();
    build.include(dir).opt_level(3).warnings(false);
    // Match the cgo flags used by the Go bindings.
    build.flag_if_supported("-fomit-frame-pointer");
    for src in SOURCES {
        let path = dir.join(src);
        println!("cargo:rerun-if-changed={}", path.display());
        build.file(path);
    }
    for hdr in [
        "config.h",
        "deterministic.h",
        "falcon.h",
        "fpr.h",
        "inner.h",
    ] {
        println!("cargo:rerun-if-changed={}", dir.join(hdr).display());
    }
    println!("cargo:rerun-if-changed=csrc/check_sizes.c");
    build.file("csrc/check_sizes.c");
    build.compile("falcon");
}

extern crate gcc;

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:include={}", root.join("src").display());

    gcc::Config::new()
        .file("src/shn.c")
        .compile("libshannon.a");
}


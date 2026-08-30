use std::{fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=capability.json");
    println!("cargo:rerun-if-changed=schemas");
    println!("cargo:rerun-if-changed=src/generated.rs");
    let artifacts = lenso_contract_codegen::generate(Path::new("capability.json"))
        .expect("Project Automation Capability contract generation failed");
    let rust_path = Path::new("src/generated.rs");
    let committed_rust = fs::read_to_string(rust_path)
        .expect("generated Project Automation Rust binding is missing");
    assert_eq!(
        committed_rust, artifacts.rust,
        "generated Project Automation Rust binding is stale; regenerate src/generated.rs"
    );
}

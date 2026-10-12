fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../quickshare_wire.proto");
    prost_build::compile_protos(&["../quickshare_wire.proto"], &[".."])?;
    Ok(())
}

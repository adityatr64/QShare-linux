fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = if std::path::Path::new("proto/quickshare_wire.proto").exists() {
        "proto/quickshare_wire.proto"
    } else {
        "../quickshare_wire.proto"
    };
    let proto_dir = if std::path::Path::new("proto").exists() {
        "proto"
    } else {
        ".."
    };
    println!("cargo:rerun-if-changed={}", proto_file);
    prost_build::compile_protos(&[proto_file], &[proto_dir])?;
    Ok(())
}

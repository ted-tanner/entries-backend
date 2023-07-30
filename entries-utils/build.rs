use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    const PROTO_DIR: &[&str] = &["protobuf"];
    const SCHEMA_FILE: &str = "schema.proto";
    const PROTO_RS_FILE: &str = "entries.serverschema.rs";
    const PROTO_RS_DEST: &[&str] = &["entries-utils", "src", "messages", "protobuf.rs"];

    let cwd = std::env::current_dir()?;
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let import_dir = PathBuf::from_iter([&cwd, &"..".into(), &PROTO_DIR.iter().collect()]);
    let server_schema = PathBuf::from_iter([&import_dir, &SCHEMA_FILE.into()]);

    println!("cargo:rerun-if-changed={}", server_schema.display());

    prost_build::compile_protos(&[server_schema], &[import_dir])?;

    let proto_rs = PathBuf::from_iter([out_dir, PROTO_RS_FILE.into()]);
    let dest = PathBuf::from_iter([cwd, "..".into(), PROTO_RS_DEST.iter().collect()]);

    std::fs::copy(proto_rs, dest)?;

    Ok(())
}

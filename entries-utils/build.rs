use std::fs::File;
use std::io::Write;
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

    let mut prost_build_config = prost_build::Config::new();
    prost_build_config.message_attribute(".", "#[derive(Zeroize)]");
    prost_build_config.compile_protos(&[server_schema], &[import_dir])?;

    let proto_rs = PathBuf::from_iter([out_dir, PROTO_RS_FILE.into()]);
    let dest = PathBuf::from_iter([cwd, "..".into(), PROTO_RS_DEST.iter().collect()]);

    let mut dest_file = File::create(dest)?;

    writeln!(dest_file, "use zeroize::Zeroize;")?;
    writeln!(dest_file)?;

    dest_file.write_all(&std::fs::read(proto_rs)?)?;

    Ok(())
}

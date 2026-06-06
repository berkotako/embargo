fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        // Include the google/protobuf well-known types path.
        .compile_protos(&["../../proto/embargo.proto"], &["../../proto"])?;
    Ok(())
}

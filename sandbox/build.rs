fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Reuse the engine's gRPC contract; we only need the client for ReportEvent.
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["../engine/proto/embargo.proto"], &["../engine/proto"])?;
    Ok(())
}

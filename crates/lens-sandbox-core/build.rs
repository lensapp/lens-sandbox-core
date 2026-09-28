fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "channel")]
    generate_isolation_boundary();
}

/// Both methods are bidirectional streams of opaque chunks; the chunks carry
/// the messages of `channel`, so the service itself never changes.
#[cfg(feature = "channel")]
fn generate_isolation_boundary() {
    let chunk_stream = |name: &str, route: &str| {
        tonic_build::manual::Method::builder()
            .name(name)
            .route_name(route)
            .input_type("bytes::Bytes")
            .output_type("bytes::Bytes")
            .codec_path("crate::channel::ChunkCodec")
            .client_streaming()
            .server_streaming()
            .build()
    };
    let service = tonic_build::manual::Service::builder()
        .name("IsolationBoundary")
        .package("lens.sandbox.channel.v1")
        .method(chunk_stream("exchange", "Exchange"))
        .method(chunk_stream("mediate", "Mediate"))
        .build();
    tonic_build::manual::Builder::new().compile(&[service]);
}

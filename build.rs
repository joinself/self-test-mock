fn main() {
    tonic_build::compile_protos("src/protocol/api/api.proto")
        .expect("failed to build protobuf bindings");
}

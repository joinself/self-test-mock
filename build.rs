fn main() {
    tonic_build::compile_protos("src/protocol/rpc/rpc.proto")
        .expect("failed to build protobuf bindings");
}

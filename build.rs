use libbpf_cargo::SkeletonBuilder;
use std::{
    env,
    path::{Path, PathBuf},
};

fn build_bpf(src: &'static str, out: &Path) {
    // libbpf-cargo doesn't include *all* of clang's default system includes
    // (although it should) so when we want to use certain headers, we need to
    // manually include them. To find which to include, see libbpf's Makefile:
    // https://github.com/libbpf/libbpf-bootstrap/pull/2/files#diff-3e2513390df543315686d7c85bd901ca9256268970032298815d2f893a9f0685R14
    // You can also consider relying on gcc-multilib:
    // https://github.com/xdp-project/xdp-tutorial/commit/4a5abdc431bde0968886131731080143f4cb5e31
    match SkeletonBuilder::new()
        .debug(true)
        .source(src)
        .clang_args("-idirafter /usr/include/x86_64-linux-gnu")
        .build_and_generate(out)
    {
        Ok(_) => {}
        Err(err) => match err {
            libbpf_cargo::Error::Build(build_err) => panic!("{}", build_err),
            libbpf_cargo::Error::Generate(gen_err) => panic!("{}", gen_err),
        },
    }
}

fn build_cgroupdev() {
    const SRC: &str = "src/bpf/cgroupdev.bpf.c";

    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("cgroupdev.skel.rs");

    build_bpf(SRC, out.as_path());

    println!("cargo:rerun-if-changed={}", SRC);
}

fn build_cgroupsysctl() {
    const SRC: &str = "src/bpf/cgroupsysctl.bpf.c";

    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("cgroupsysctl.skel.rs");

    build_bpf(SRC, out.as_path());

    println!("cargo:rerun-if-changed={}", SRC);
}

fn main() {
    build_cgroupdev();
    build_cgroupsysctl();
}

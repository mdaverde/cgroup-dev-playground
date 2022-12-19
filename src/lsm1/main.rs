use libbpf_rs::libbpf_sys;
use std::sync::{self, atomic};

mod lsm1 {
    include!(concat!(env!("OUT_DIR"), "/lsm1.skel.rs"));
}

fn main() {
    let running = sync::Arc::new(atomic::AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, atomic::Ordering::SeqCst);
        println!("Ending process after end of next loop...");
    })
    .expect("failed to set ctrl-c handler");

    let mut skel_builder = lsm1::Lsm1SkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let open_skel = skel_builder.open().unwrap();

    let mut skel = open_skel.load().unwrap();
    let mut progs = skel.progs_mut();
    let file_open_lsm_prog = progs.file_open_lsm();

    let file_open_lsm_prog_fd = file_open_lsm_prog.fd();

    let ret = unsafe {
        libbpf_sys::bpf_prog_attach(
            file_open_lsm_prog_fd,
            123, // Should be target fd but doesn't matter to show leak
            libbpf_rs::ProgramAttachType::LsmMac as u32,
            0,
        )
    };
    if ret != 0 {
        // If attachment failed, then LSM program would leak. More information &
        // resolution here: https://lore.kernel.org/all/CAKH8qBvRnDFhWEkZr9UNdznKNoCcjsZNBXeSVpXWooFhm5+C3g@mail.gmail.com/
        panic!("did not raw attach lsm program: {} {}", ret, -unsafe {
            *libc::__errno_location()
        });
    }

    println!("Running... Ctrl-C to quit");
    while running.load(atomic::Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::new(1, 0))
    }
}

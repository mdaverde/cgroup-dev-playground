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

    println!("Running... Ctrl-C to quit");
    while running.load(atomic::Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::new(1, 0))
    }
}

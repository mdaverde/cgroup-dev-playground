use anyhow::{bail, Result};
use libbpf_rs::libbpf_sys;
use libbpf_rs::libbpf_sys::libbpf_major_version;
use std::ffi::{CString, OsStr};
use std::fs::OpenOptions;
use std::os::unix::prelude::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{
    ffi::CStr,
    fs::{DirBuilder, File},
    path::PathBuf,
    str::FromStr,
};

mod cgroupdev {
    include!(concat!(env!("OUT_DIR"), "/cgroupdev.skel.rs"));
}

const CGROUP_MOUNT_PATH: &str = "/sys/fs/cgroup";

struct TmpCgroup {
    path: CString,
}

impl TmpCgroup {
    // Would be try_new but we panic if our assertions fails
    pub fn new<T: AsRef<Path>>(cgroup_path: T) -> Self {
        DirBuilder::new()
            .create(cgroup_path.as_ref())
            .expect("could not create cgroup dir");

        let mut path_bytes = cgroup_path.as_ref().as_os_str().as_bytes().to_vec();
        path_bytes.push(b'\0');

        let cgroup_path =
            CString::from_vec_with_nul(path_bytes).expect("path bytes not correctly formed");

        TmpCgroup { path: cgroup_path }
    }

    pub fn create(&self) -> OwnedFd {
        let path = Path::new(OsStr::from_bytes(self.path.as_c_str().to_bytes()));
        OpenOptions::new()
            .read(true)
            .open(path)
            .expect("could not open cgroup dir")
            .into()
    }

    // Would be try_delete but we panic if assertions fail
    pub fn delete(&mut self) {
        let path_ptr = self.path.as_ptr();
        if unsafe { libc::rmdir(path_ptr) } != 0 {
            eprintln!("could not delete cgroup: {:?}", self.path);
        } else {
            println!("deleted cgroup: {:?}", self.path);
        }
    }
}

impl Drop for TmpCgroup {
    fn drop(&mut self) {
        self.delete();
    }
}

/* Cases:
 *   1) Redundant links between the same program fd and cgroup fd result in
 *      successful (redundant) link creation but bpf(BPF_PROG_QUERY) also returns
 *      redundant prog_ids to signify multiple attachments of the same program on the object
 *   2) You can not *directly* attach the same program fds to the same cgroup fd
 */

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("Ending process after end of next loop...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("failed to set ctrl-c handler");

    let cgroup1 = TmpCgroup::new(format!("{}/{}", CGROUP_MOUNT_PATH, "tmp10"));
    let cgroup1_fd = cgroup1.create();

    let mut skel_builder = cgroupdev::CgroupdevSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_skel = skel_builder.open().expect("could not open");

    // Not sure it's possible to load a specific bpf program
    let mut skel = open_skel.load().expect("could not load");

    let mut progs = skel.progs_mut();
    let bpf_prog1 = progs.bpf_prog1();

    /*
     * bpf links: only is alive for the lifetime of the process
     * Seems like this is fd-based (only alive locally)? Is this the case with all links??
     */

    let bpf_prog1_link = bpf_prog1
        .attach_cgroup(cgroup1_fd.as_raw_fd())
        .expect("original link: attach bpf_prog1 to cgroup");

    /*
     * TEST 1: Try attaching same bpf program to same cgroup through new link
     * RESULT: Multiple links are created. Will show up in bpftool link and bpftool cgroup tree
     */

    let bpf_prog1_link2 = bpf_prog1
        .attach_cgroup(cgroup1_fd.as_raw_fd())
        .expect("link2: attach bpf_prog1 to cgroup");

    let bpf_prog1_link3 = bpf_prog1
        .attach_cgroup(cgroup1_fd.as_raw_fd())
        .expect("link2: attach bpf_prog1 to cgroup");

    // Direct attachments ON TOP OF redundant link attachment
    let direct_attach_result1 = unsafe {
        libbpf_sys::bpf_prog_attach(
            bpf_prog1.fd(),
            cgroup1_fd.as_raw_fd(),
            libbpf_rs::ProgramAttachType::CgroupDevice as u32,
            libbpf_sys::BPF_F_ALLOW_MULTI,
        )
    };
    if direct_attach_result1 != 0 {
        panic!(
            "could not attach bpf program to cgroup dev. result: {} errno: {}",
            direct_attach_result1,
            -unsafe { *libc::__errno_location() }
        );
    } else {
        println!("directly attached 1");
    }

    /* Test 2: Can't **directly** attach multiple times, even with ALLOW_MULTI */
    // let direct_attach_result2 = unsafe {
    //     libbpf_sys::bpf_prog_attach(
    //         bpf_prog1.fd(),
    //         cgroup1_fd.as_raw_fd(),
    //         libbpf_rs::ProgramAttachType::CgroupDevice as u32,
    //         libbpf_sys::BPF_F_ALLOW_MULTI,
    //     )
    // };
    // if direct_attach_result2 != 0 {
    //     panic!(
    //         "could not attach bpf program to cgroup dev. result: {} errno: {}",
    //         direct_attach_result2,
    //         -unsafe { *libc::__errno_location() }
    //     );
    // } else {
    //     println!("directly attached 2");
    // }

    let child_cgroup = TmpCgroup::new(format!("{}/{}/{}", CGROUP_MOUNT_PATH, "tmp10", "tmpchild"));
    let child_cgroup_fd = child_cgroup.create();

    let bpf_prog1_child_link1 = bpf_prog1
        .attach_cgroup(child_cgroup_fd.as_raw_fd())
        .expect("could not attach to tmpchild cgroup");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::new(5, 0))
    }
}

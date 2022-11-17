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
    pub fn new(name: &'static str) -> Self {
        let mut path_string =
            String::from_str(CGROUP_MOUNT_PATH).expect("mount path could not parse");
        path_string.push('/');
        path_string.push_str(name);

        DirBuilder::new()
            .create(path_string.as_str())
            .expect("could not create cgroup dir");

        let mut path_bytes = path_string.into_bytes();
        path_bytes.push(b'\0');

        let cgroup_path =
            CString::from_vec_with_nul(path_bytes).expect("path bytes not correctly formed");

        TmpCgroup { path: cgroup_path }
    }

    pub fn fd(&self) -> OwnedFd {
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

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("Ending process after end of next loop...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("failed to set ctrl-c handler");

    let cgroup1 = TmpCgroup::new("tmp10");

    let mut skel_builder = cgroupdev::CgroupdevSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_skel = skel_builder.open().expect("could not open");

    // Not sure it's possible to load a specific bpf program
    let mut skel = open_skel.load().expect("could not load");

    let cgroup1_fd = cgroup1.fd();

    // Only is alive for the lifetime of the process
    // Seems like this is fd-based (only alive locally)? Is this the case with all links??
    let bpf_prog1_link = skel
        .progs_mut()
        .bpf_prog1()
        .attach_cgroup(cgroup1_fd.as_raw_fd())
        .expect("attach bpf_prog1 to cgroup");

    // Stays around even after program exits
    // let mut progs = skel.progs_mut();
    // let bpf_prog1_link = progs.bpf_prog1();

    // if unsafe {
    //     libbpf_sys::bpf_prog_attach(
    //         bpf_prog1_link.fd(),
    //         cgroup1_fd.as_raw_fd(),
    //         libbpf_rs::ProgramAttachType::CgroupDevice as u32,
    //         0,
    //     )
    // } != 0
    // {
    //     panic!("could not attach bpf program to cgroup dev");
    // }

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::new(5, 0))
    }
}

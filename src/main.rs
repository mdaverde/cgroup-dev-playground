use anyhow::{bail, Result};
use std::ffi::CString;
use std::os::unix::prelude::*;
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

    // Would be try_delete but we panic if assertions fail
    pub fn delete(&mut self) {
        let path_ptr = self.path.as_ptr();
        if unsafe { libc::rmdir(path_ptr) } != 0 {
            panic!("could not delete cgroup: {:?}", self.path)
        }
    }
}

impl Drop for TmpCgroup {
    fn drop(&mut self) {
        self.delete();
    }
}

fn main() {
    let _ = TmpCgroup::new("tmp10");
    let _ = TmpCgroup::new("tmp11");
}

use anyhow::{anyhow, Result};
use log::warn;
use procfs;
use std::collections::{hash_map::Entry, HashMap};
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::path::Path;

enum BinderType {
    BINDER,
    HWBINDER,
    VNDBINDER,
}

impl TryFrom<std::path::PathBuf> for BinderType {
    type Error = anyhow::Error;

    fn try_from(path: std::path::PathBuf) -> std::prelude::v1::Result<Self, Self::Error> {
        match path {
            _ if path == Path::new("/dev/binder") || path == Path::new("/dev/binderfs/binder") => {
                Ok(BinderType::BINDER)
            }
            _ if path == Path::new("/dev/hwbinder")
                || path == Path::new("/dev/binderfs/hwbinder") =>
            {
                Ok(BinderType::HWBINDER)
            }
            _ if path == Path::new("/dev/vndbinder")
                || path == Path::new("/dev/binderfs/vndbinder") =>
            {
                Ok(BinderType::VNDBINDER)
            }
            _ => Err(anyhow!("Not a binder path")),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct ProcessKey {
    pid: i32,
    tid: i32,
}

#[derive(Debug)]
pub struct ProcessInfo {
    cmdline: String,
    comm: String,
    binder_fd: Option<i32>,
    hwbinder_fd: Option<i32>,
    vndbinder_fd: Option<i32>,
}

impl ProcessInfo {
    pub fn get_binder_name(&self, fd: i32) -> Option<&'static str> {
        if self.binder_fd.is_some_and(|x| fd == x) {
            return Some("/dev/binder");
        }
        if self.hwbinder_fd.is_some_and(|x| fd == x) {
            return Some("/dev/hwbinder");
        }
        if self.vndbinder_fd.is_some_and(|x| fd == x) {
            return Some("/dev/vndbinder");
        }
        None
    }

    pub fn get_cmdline(&self) -> &str {
        &self.cmdline
    }

    pub fn get_comm(&self) -> &str {
        &self.comm
    }
}

pub struct ProcessCache {
    map: HashMap<ProcessKey, ProcessInfo>,
}

impl ProcessCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    fn create_process_info(tid: u32) -> Result<ProcessInfo> {
        let proc = procfs::process::Process::new(tid as i32)?;
        let cmdline = proc.cmdline()?;
        let cmdline = cmdline.into_iter().nth(0).unwrap_or_default();

        let mut proc_info = ProcessInfo {
            cmdline: cmdline,
            comm: proc.stat()?.comm,
            binder_fd: None,
            hwbinder_fd: None,
            vndbinder_fd: None,
        };

        for fd in proc.fd()? {
            if fd.is_err() {
                continue;
            }
            let fd = fd.unwrap();
            let binder_type = match fd.target {
                procfs::process::FDTarget::Path(path) => BinderType::try_from(path).ok(),
                _ => None,
            };
            if binder_type.is_none() {
                continue;
            }
            // TODO - check that there is only one fd of each type / support multiple fds (does anybody do that?)
            match binder_type.unwrap() {
                BinderType::BINDER => proc_info.binder_fd = Some(fd.fd),
                BinderType::HWBINDER => proc_info.hwbinder_fd = Some(fd.fd),
                BinderType::VNDBINDER => proc_info.vndbinder_fd = Some(fd.fd),
            }
            if proc_info.binder_fd.is_some()
                && proc_info.hwbinder_fd.is_some()
                && proc_info.vndbinder_fd.is_some()
            {
                break;
            }
        }

        if proc_info.binder_fd.is_none()
            && proc_info.hwbinder_fd.is_none()
            && proc_info.vndbinder_fd.is_none()
        {
            return Err(anyhow!("Thread {} doesn't have any open binder fds", tid));
        }

        Ok(proc_info)
    }

    pub fn get_proc(&mut self, pid: i32, tid: i32, comm: Option<&str>) -> Result<&ProcessInfo> {
        let key = ProcessKey { pid, tid };
        let proc_info = match self.map.entry(key.clone()) {
            Entry::Occupied(mut proc_info) => {
                if let Some(comm) = comm {
                    if comm.ne(&proc_info.get().comm) {
                        proc_info.insert(Self::create_process_info(tid as u32)?);
                    }
                }
                proc_info.into_mut()
            }
            Entry::Vacant(v) => v.insert(Self::create_process_info(tid as u32)?),
        };

        Ok(proc_info)
    }

    pub fn invalidate_proc(&mut self, pid: i32, tid: i32) -> Option<ProcessInfo> {
        self.map.remove(&ProcessKey { pid, tid })
    }
}

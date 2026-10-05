//! Facts about the running kernel that decide which programs can be loaded and how.

use std::{ffi::CString, path::Path, ptr::NonNull};

use libbpf_rs::libbpf_sys;

/// Kernel BTF of vmlinux and of the modules looked at so far, used to check that the
/// functions the fentry programs attach to exist before loading the object. BTF is
/// only read when it is first needed.
#[derive(Default)]
pub struct KernelBtf {
    vmlinux: Option<Option<NonNull<libbpf_sys::btf>>>,
    modules: Vec<(String, Option<NonNull<libbpf_sys::btf>>)>,
}

impl KernelBtf {
    fn vmlinux(&mut self) -> Option<NonNull<libbpf_sys::btf>> {
        *self
            .vmlinux
            .get_or_insert_with(|| NonNull::new(unsafe { libbpf_sys::btf__load_vmlinux_btf() }))
    }

    fn module(&mut self, module: &str) -> Option<NonNull<libbpf_sys::btf>> {
        if let Some((_, btf)) = self.modules.iter().find(|(name, _)| name == module) {
            return *btf;
        }
        let btf = match (self.vmlinux(), CString::new(module)) {
            (Some(vmlinux), Ok(name)) if Path::new("/sys/kernel/btf").join(module).exists() => {
                NonNull::new(unsafe {
                    libbpf_sys::btf__load_module_btf(name.as_ptr(), vmlinux.as_ptr())
                })
            }
            _ => None,
        };
        self.modules.push((module.to_string(), btf));
        btf
    }

    /// Whether `func` exists in vmlinux or, if given, in the BTF of `module`
    pub fn has_func(&mut self, module: Option<&str>, func: &str) -> bool {
        let Ok(name) = CString::new(func) else {
            return false;
        };
        let find = |btf: NonNull<libbpf_sys::btf>| unsafe {
            libbpf_sys::btf__find_by_name_kind(
                btf.as_ptr(),
                name.as_ptr(),
                libbpf_sys::BTF_KIND_FUNC,
            ) > 0
        };
        if self.vmlinux().is_some_and(find) {
            return true;
        }
        // Module BTF is split BTF on top of vmlinux, a lookup also searches vmlinux
        module
            .and_then(|module| self.module(module))
            .is_some_and(find)
    }

    /// The first of `candidates` that exists, see `has_func`
    pub fn find_func<'a>(
        &mut self,
        module: Option<&str>,
        candidates: &[&'a str],
    ) -> Option<&'a str> {
        candidates
            .iter()
            .copied()
            .find(|func| self.has_func(module, func))
    }

    /// Whether vmlinux BTF could be read at all. Without it no check is possible.
    pub fn available(&mut self) -> bool {
        self.vmlinux().is_some()
    }
}

impl Drop for KernelBtf {
    fn drop(&mut self) {
        // Module BTF references vmlinux BTF, free it first
        for (_, btf) in self.modules.drain(..) {
            if let Some(btf) = btf {
                unsafe { libbpf_sys::btf__free(btf.as_ptr()) };
            }
        }
        if let Some(Some(vmlinux)) = self.vmlinux.take() {
            unsafe { libbpf_sys::btf__free(vmlinux.as_ptr()) };
        }
    }
}

/// Kernel (major, minor) version from uname
pub fn kernel_version() -> Option<(u32, u32)> {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return None;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy();
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|part| part.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??))
}

pub mod bbr;
pub mod cubic;
pub mod cwnd;
pub mod headers;
pub mod kernel;
pub mod tracepoints;

use libbpf_rs::{Link, MapCore, MapHandle, MapMut, OpenProgramMut, ProgramMut};
use log::{info, warn};

use super::{errors::EBPFRunnerError, host::KernelBtf};

/// Attaches a program at the target given by its section and keeps the link
pub fn attach(program: &ProgramMut<'_>, links: &mut Vec<Link>) -> Result<(), EBPFRunnerError> {
    let link = program
        .attach()
        .map_err(|source| EBPFRunnerError::AttachError {
            name: program.name().to_string_lossy().into_owned(),
            source,
        })?;
    links.push(link);
    Ok(())
}

/// Own handle to a map, it stays open after the skeleton is dropped
pub fn handle(map: &MapMut<'_>) -> Result<MapHandle, EBPFRunnerError> {
    MapHandle::try_from(map).map_err(|source| EBPFRunnerError::MapError {
        name: map.name().to_string_lossy().into_owned(),
        source,
    })
}

/// Points an fentry program at the first of `candidates` (current name first, then names
/// used by other kernels) that exists in the kernel BTF. If none does, the program is
/// not loaded and a warning is logged. Returns whether the program stays enabled.
pub fn retarget(
    program: &mut OpenProgramMut<'_>,
    btf: &mut KernelBtf,
    module: Option<&str>,
    candidates: &[&str],
) -> Result<bool, EBPFRunnerError> {
    let name = program.name().to_string_lossy().into_owned();
    match btf.find_func(module, candidates) {
        Some(func) if func == candidates[0] => Ok(true),
        Some(func) => {
            info!("Attaching {} to {}", name, func);
            program
                .set_attach_target(0, Some(func.to_string()))
                .map_err(|source| EBPFRunnerError::AttachError { name, source })?;
            Ok(true)
        }
        None => {
            warn!(
                "None of the kernel functions {:?} exists, {} is disabled",
                candidates, name
            );
            program.set_autoload(false);
            Ok(false)
        }
    }
}

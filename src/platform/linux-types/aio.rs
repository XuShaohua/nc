use super::signal::*;
use super::types::*;

// FROM fs/aio.c
#[repr(C)]
pub struct aio_sigset_t<'a> {
    pub sigmask: &'a sigset_t,
    pub sigsetsize: size_t,
}

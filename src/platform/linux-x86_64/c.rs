
use super::nums::*;
use super::syscall0;
use super::types::*;

pub fn getpid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPID) as pid_t;
    }
}

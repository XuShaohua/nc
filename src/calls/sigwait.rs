/// Select a set of signals
pub unsafe fn sigwait(set: &sigset_t, sig: &mut i32) -> Result<(), Errno> {
    let set_ptr = core::ptr::from_ref(set) as usize;
    let sig_ptr = core::ptr::from_mut(sig) as usize;
    unsafe { syscall2(SYS_SIGWAIT, set_ptr, sig_ptr).map(drop) }
}

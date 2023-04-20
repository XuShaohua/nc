/// Destroys the processor set specified by `psid`.
pub unsafe fn pset_destroy(psid: &psetid_t) -> Result<(), Errno> {
    let psid_ptr = psid as *const psetid_t as usize;
    syscall1(SYS_PSET_DESTROY, psid_ptr).map(drop)
}

/// Creates a processor set, and returns its ID into `psid`.
pub unsafe fn pset_create(psid: &mut psetid_t) -> Result<(), Errno> {
    let psid_ptr = core::ptr::from_mut(psid) as usize;
    unsafe { syscall1(SYS_PSET_CREATE, psid_ptr).map(drop) }
}

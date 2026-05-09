pub unsafe fn freebsd10__umtx_unlock(umtx: &mut umtx_t) -> Result<(), Errno> {
    let umtx_ptr = core::ptr::from_mut(umtx) as usize;
    unsafe { syscall1(SYS_FREEBSD10__UMTX_UNLOCK, umtx_ptr).map(drop) }
}

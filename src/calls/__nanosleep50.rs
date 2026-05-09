/// High resolution sleep.
pub unsafe fn __nanosleep50(req: &timespec_t, rem: Option<&mut timespec_t>) -> Result<(), Errno> {
    let req_ptr = core::ptr::from_ref(req) as usize;
    let rem_ptr = rem.map_or(0, |rem| core::ptr::from_mut(rem) as usize);
    unsafe { syscall2(SYS___NANOSLEEP50, req_ptr, rem_ptr).map(drop) }
}

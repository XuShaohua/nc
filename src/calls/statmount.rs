pub unsafe fn statmount(
    req: &mnt_id_req_t,
    buf: &mut [statmount_t],
    flags: u32,
) -> Result<(), Errno> {
    let req_ptr = core::ptr::from_ref(req) as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buf_size = buf.len();
    let flags = flags as usize;
    unsafe { syscall4(SYS_STATMOUNT, req_ptr, buf_ptr, buf_size, flags).map(drop) }
}

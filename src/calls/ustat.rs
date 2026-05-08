/// Get filesystem statistics
pub unsafe fn ustat(dev: dev_t, ubuf: &mut ustat_t) -> Result<(), Errno> {
    let dev = dev as usize;
    let ubuf_ptr = core::ptr::from_mut(ubuf) as usize;
    unsafe { syscall2(SYS_USTAT, dev, ubuf_ptr).map(drop) }
}

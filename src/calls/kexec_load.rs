/// Load a new kernel for later execution.
pub unsafe fn kexec_load(
    entry: usize,
    nr_segments: usize,
    segments: &mut kexec_segment_t,
    flags: usize,
) -> Result<(), Errno> {
    let segments_ptr = segments as *mut kexec_segment_t as usize;
    syscall4(SYS_KEXEC_LOAD, entry, nr_segments, segments_ptr, flags).map(drop)
}

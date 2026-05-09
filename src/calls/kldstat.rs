/// Get status of a kld file.
pub unsafe fn kldstat(file_id: i32, stat: &mut kld_file_stat_t) -> Result<(), Errno> {
    let file_id = file_id as usize;
    let stat_ptr = core::ptr::from_mut(stat) as usize;
    unsafe { syscall2(SYS_KLDSTAT, file_id, stat_ptr).map(drop) }
}

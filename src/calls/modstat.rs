/// Get status of a kernel module.
pub unsafe fn modstat(modid: i32, stat: &mut module_stat_t) -> Result<(), Errno> {
    let modid = modid as usize;
    let stat_ptr = core::ptr::from_mut(stat) as usize;
    unsafe { syscall2(SYS_MODSTAT, modid, stat_ptr).map(drop) }
}

/// Fast user-space locking.
pub unsafe fn futex(
    uaddr: &AtomicU32,
    op: i32,
    val: u32,
    utime: Option<&timespec_t>,
    uaddr2: Option<&AtomicU32>,
    val3: u32,
) -> Result<i32, Errno> {
    let uaddr_ptr = uaddr as *const AtomicU32 as usize;
    let op = op as usize;
    let val = val as usize;
    let utime_ptr = utime.map_or(core::ptr::null::<timespec_t>() as usize, |time_ref| {
        time_ref as *const timespec_t as usize
    });
    let uaddr2_ptr = uaddr2.map_or(core::ptr::null::<AtomicU32>() as usize, |uaddr2_ref| {
        uaddr2_ref as *const AtomicU32 as usize
    });
    let val3 = val3 as usize;
    syscall6(SYS_FUTEX, uaddr_ptr, op, val, utime_ptr, uaddr2_ptr, val3).map(|ret| ret as i32)
}

/// Fast user-space locking.
pub unsafe fn futex(
    uaddr: &mut i32,
    futex_op: i32,
    val: u32,
    timeout: &mut timespec_t,
    uaddr2: &mut i32,
    val3: i32,
) -> Result<i32, Errno> {
    let uaddr_ptr = uaddr as *mut i32 as usize;
    let futex_op = futex_op as usize;
    let val = val as usize;
    let timeout_ptr = timeout as *mut timespec_t as usize;
    let uaddr2_ptr = uaddr2 as *mut i32 as usize;
    let val3 = val3 as usize;
    syscall6(
        SYS_FUTEX,
        uaddr_ptr,
        futex_op,
        val,
        timeout_ptr,
        uaddr2_ptr,
        val3,
    )
    .map(|ret| ret as i32)
}

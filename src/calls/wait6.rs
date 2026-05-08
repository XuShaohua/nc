/// Wait for process to change state.
pub unsafe fn wait6(
    idtype: idtype_t,
    id: id_t,
    status: &mut i32,
    options: i32,
    wrusage: &mut wrusage_t,
    info: &mut siginfo_t,
) -> Result<pid_t, Errno> {
    let idtype = idtype as usize;
    let id = id as usize;
    let status_ptr = core::ptr::from_mut(status) as usize;
    let options = options as usize;
    let wrusage_ptr = core::ptr::from_mut(wrusage) as usize;
    let info_ptr = core::ptr::from_mut(info) as usize;
    unsafe {
        syscall6(
            SYS_WAIT6,
            idtype,
            id,
            status_ptr,
            options,
            wrusage_ptr,
            info_ptr,
        )
        .map(|ret| ret as pid_t)
    }
}

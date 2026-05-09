pub unsafe fn __cap_rights_get(
    version: i32,
    fd: i32,
    rights: &mut cap_rights_t,
) -> Result<(), Errno> {
    let version = version as usize;
    let fd = fd as usize;
    let rights_ptr = core::ptr::from_mut(rights) as usize;
    unsafe { syscall3(SYS___CAP_RIGHTS_GET, version, fd, rights_ptr).map(drop) }
}

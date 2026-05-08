/// Set login name.
pub unsafe fn setlogin(name: &str) -> Result<(), Errno> {
    let name = CString::new(name);
    let name_ptr = name.as_ptr() as usize;
    unsafe { syscall1(SYS_SETLOGIN, name_ptr).map(drop) }
}

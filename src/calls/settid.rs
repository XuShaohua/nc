/// Set the per-thread override identity.
pub unsafe fn settid(uid: uid_t, gid: gid_t) -> Result<(), Errno> {
    let uid = uid as usize;
    let gid = gid as usize;
    unsafe { syscall2(SYS_SETTID, uid, gid).map(drop) }
}

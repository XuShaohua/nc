/// Detach an association from a one-to-many socket to its own fd
pub unsafe fn sctp_peeloff(socket: i32, id: sctp_assoc_t) -> Result<i32, Errno> {
    let socket = socket as usize;
    let id = id as usize;
    syscall2(SYS_CLOSE, fd).map(|val| val as i32)
}

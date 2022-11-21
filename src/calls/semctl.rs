/// System V semaphore control operations
pub unsafe fn semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> Result<i32, Errno> {
    let semid = semid as usize;
    let semnum = semnum as usize;
    let cmd = cmd as usize;
    syscall4(SYS_SEMCTL, semid, semnum, cmd, arg).map(|ret| ret as i32)
}

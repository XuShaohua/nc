/// Send a message to message queue (REALTIME)
pub unsafe fn kmq_timedsend(mqd: i32, msg: &[u8], msg_prio: u32) -> Result<(), Errno> {
    let mqd = mqd as usize;
    let msg_ptr = msg.as_ptr() as usize;
    let msg_len = msg.len();
    let msg_prio = msg_prio as usize;
    syscall4(SYS_KMQ_TIMEDSEND, mqd, msg_ptr, msg_len, msg_prio).map(drop)
}

/// Notify process that a message is available (REALTIME)
pub unsafe fn kmq_notify(mqd: i32, event: &sigevent_t) -> Result<(), Errno> {
    let mqd = mqd as usize;
    let event_ptr = core::ptr::from_ref(event) as usize;
    unsafe { syscall2(SYS_KMQ_NOTIFY, mqd, event_ptr).map(drop) }
}

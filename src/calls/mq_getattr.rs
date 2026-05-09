/// Get message queue attributes (realtime)
pub unsafe fn mq_getattr(mqdes: mqd_t, attr: Option<&mut mq_attr_t>) -> Result<(), Errno> {
    let mqdes = mqdes as usize;
    let attr_ptr = attr.map_or(0, |attr| core::ptr::from_mut(attr) as usize);
    unsafe { syscall2(SYS_MQ_GETATTR, mqdes, attr_ptr).map(drop) }
}

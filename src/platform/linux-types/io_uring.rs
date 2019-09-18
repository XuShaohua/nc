use super::fs::*;

#[repr(C)]
pub union io_uring_sqe_flags_t {
    pub rw_flags: rwf_t,
    pub fsync_flags: u32,
    pub poll_events: u16,
    pub sync_range_flags: u32,
    pub msg_flags: u32,
}

#[repr(C)]
pub union io_uring_sqe_buf_t {
    /// index into fixed buffers, if used
    pub buf_index: u16,

    pad2: [u64; 3],
}

/// IO submission data structure (Submission Queue Entry)
#[repr(C)]
pub struct io_uring_sqe_t {
    /// type of operation for this sqe
    pub opcode: u8,

    /// IOSQE_ flags
    pub flags: u8,

    /// ioprio for the request
    pub ioprio: u16,

    /// file descriptor to do IO on
    pub fd: i32,

    /// offset into file
    pub off: u64,

    /// pointer to buffer or iovecs
    pub addr: u64,

    /// buffer size or number of iovecs
    pub len: u32,

    pub rw_flags: io_uring_sqe_flags_t,

    /// data to be passed back at completion time
    pub user_data: u64,

    pub buf: io_uring_sqe_buf_t,
}

/// sqe->flags
/// use fixed fileset
pub const IOSQE_FIXED_FILE: u32 = 1 << 0;
/// issue after inflight IO
pub const IOSQE_IO_DRAIN: u32 = 1 << 1;
/// links next sqe
pub const IOSQE_IO_LINK: u32 = 1 << 2;

/// io_uring_setup() flags
/// io_context is polled
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
/// SQ poll thread
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
/// sq_thread_cpu is valid
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;

pub const IORING_OP_NOP: i32 = 0;
pub const IORING_OP_READV: i32 = 1;
pub const IORING_OP_WRITEV: i32 = 2;
pub const IORING_OP_FSYNC: i32 = 3;
pub const IORING_OP_READ_FIXED: i32 = 4;
pub const IORING_OP_WRITE_FIXED: i32 = 5;
pub const IORING_OP_POLL_ADD: i32 = 6;
pub const IORING_OP_POLL_REMOVE: i32 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: i32 = 8;
pub const IORING_OP_SENDMSG: i32 = 9;
pub const IORING_OP_RECVMSG: i32 = 10;

/// sqe->fsync_flags
pub const IORING_FSYNC_DATASYNC: u32 = 1 << 0;

/// IO completion data structure (Completion Queue Entry)
#[repr(C)]
pub struct io_uring_cqe_t {
    /// sqe->data submission passed back
    pub user_data: u64,

    /// result code for this event
    pub res: i32,

    pub flags: u32,
}

/// Magic offsets for the application to mmap the data it needs
pub const IORING_OFF_SQ_RING: u64 = 0;
pub const IORING_OFF_CQ_RING: u64 = 0x8000000;
pub const IORING_OFF_SQES: u64 = 0x10000000;

/// Filled with the offset for mmap(2)
#[repr(C)]
pub struct io_sqring_offsets_t {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    resv1: u32,
    resv2: u64,
}

/// sq_ring->flags
/// needs io_uring_enter wakeup
pub const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;

#[repr(C)]
pub struct io_cqring_offsets_t {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    resv: [u64; 2],
}

/// io_uring_enter(2) flags
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;

/// Passed in for io_uring_setup(2). Copied back with updated info on success
#[repr(C)]
pub struct io_uring_params_t {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    resv: [u32; 4],

    pub sq_off: io_sqring_offsets_t,
    pub cq_off: io_cqring_offsets_t,
}

/// io_uring_params->features flags
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;

/// io_uring_register(2) opcodes and arguments
pub const IORING_REGISTER_BUFFERS: i32 = 0;
pub const IORING_UNREGISTER_BUFFERS: i32 = 1;
pub const IORING_REGISTER_FILES: i32 = 2;
pub const IORING_UNREGISTER_FILES: i32 = 3;
pub const IORING_REGISTER_EVENTFD: i32 = 4;
pub const IORING_UNREGISTER_EVENTFD: i32 = 5;

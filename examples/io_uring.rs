// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

use std::mem::size_of;

pub type Result<T> = std::result::Result<T, nc::Errno>;

pub struct SubmitSeq {
    pub head: *mut u32,
    pub tail: *mut u32,
    pub ring_mask: *mut u32,
    pub ring_entries: *mut u32,
    pub flags: *mut u32,
    pub dropped: *mut u32,
    pub array: *mut u32,
    pub sqes: *mut nc::io_uring_sqe_t,

    pub sqe_head: u32,
    pub sqe_tail: u32,

    pub ring_size: nc::size_t,
    pub ring_ptr: usize,
}

pub struct CompleteSeq {
    pub head: *mut u32,
    pub tail: *mut u32,
    pub ring_mask: *mut u32,
    pub ring_entries: *mut u32,
    pub overflow: *mut u32,
    pub cqes: *mut nc::io_uring_cqe_t,

    pub ring_size: nc::size_t,
    pub ring_ptr: usize,
}

pub struct Uring {
    fd: i32,
    params: nc::io_uring_params_t,
    sq_ring_ptr: usize,
    sq_ring_size: usize,
    sq: SubmitSeq,
    cq_ring_ptr: usize,
    cq_ring_size: usize,
    cq: CompleteSeq,
    sqes: usize,
    sqes_size: usize,
}


const QUEUE_SIZE: u32 = 64;
const BUF_LEN: usize = 32 * 1024;

pub struct IoVecBuffer {
    pub read: bool,
    pub offset: nc::size_t,
    pub iov: nc::iovec_t,
    pub buf: [u8; BUF_LEN],
}

impl Default for IoVecBuffer {
    fn default() -> Self {
        let mut buf = IoVecBuffer {
            read: true,
            offset: 0,
            iov: nc::iovec_t {
                iov_base: 0,
                iov_len: 0,
            },
            buf: [0; BUF_LEN],
        };
        // Setup buffer address
        buf.iov.iov_base = buf.buf.as_ptr() as usize;
        buf
    }
}

#[derive(Default)]
pub struct BufferMask {
    pub in_use: bool,
    pub buf: Box<IoVecBuffer>,
}

pub struct BufferArray {
    len: usize,
    masks: Vec<BufferMask>,
}

impl BufferArray {
    pub fn new(len: usize) -> BufferArray {
        let masks = (0..len).map(|_| BufferMask::default()).collect();
        BufferArray {
            len,
            masks,
        }
    }

    pub fn acquire(&mut self) -> Option<&mut IoVecBuffer> {
        for item in self.masks.iter_mut() {
            if !item.in_use {
                item.in_use = true;
                return Some(&mut (*item.buf));
            }
        }
        None
    }

    pub fn release(&mut self, data: *mut IoVecBuffer) {
        for item in self.masks.iter_mut() {
            if (&mut *item.buf as *mut IoVecBuffer) == data {
                item.in_use = false;
            }
        }
    }
}

impl Uring {
    fn setup(entries: u32) -> Result<Uring> {
        let mut params = nc::io_uring_params_t::default();
        let fd = nc::io_uring_setup(entries, &mut params)?;

        let sq_ring_size: usize = params.sq_off.array as usize + params.sq_entries as usize * size_of::<usize>();
        let cq_ring_size: usize = params.cq_off.cqes as usize + params.cq_entries as usize * size_of::<nc::io_uring_cqe_t>();
        let sq_ring_ptr = nc::mmap(0, sq_ring_size, nc::PROT_READ | nc::PROT_WRITE,
        nc::MAP_SHARED | nc::MAP_POPULATE, fd, nc::IORING_OFF_SQ_RING)?;
        let cq_ring_ptr = nc::mmap(0, cq_ring_size, nc::PROT_READ | nc::PROT_WRITE,
        nc::MAP_SHARED | nc::MAP_POPULATE, fd, nc::IORING_OFF_CQ_RING)?;

        let sqes_size = params.sq_entries as usize * size_of::<nc::io_uring_sqe_t>();
        let sqes = nc::mmap(0, sqes_size, nc::PROT_READ | nc::PROT_WRITE, nc::MAP_SHARED | nc::MAP_POPULATE,
        fd, nc::IORING_OFF_SQES)?;

        let sq = SubmitSeq{
          head: (sq_ring_ptr + (params.sq_off.head as *const u32 as usize)) as *mut u32,
            tail: (sq_ring_ptr + (params.sq_off.tail as *const u32 as usize)) as *mut u32,
            ring_mask: (sq_ring_ptr + (params.sq_off.ring_mask as *const u32 as usize)) as *mut u32,
            ring_entries: (sq_ring_ptr + (params.sq_off.ring_entries as *const u32 as usize)) as *mut u32,
            flags: (sq_ring_ptr + (params.sq_off.flags as *const u32 as usize)) as *mut u32,
            dropped: (sq_ring_ptr + (params.sq_off.dropped as *const u32 as usize)) as *mut u32,
            array: (sq_ring_ptr + (params.sq_off.array as *const u32 as usize)) as *mut u32,
            sqes: sqes as *mut nc::io_uring_sqe_t,
            sqe_head: 0,
            sqe_tail: 0,
            ring_size: sq_ring_size,
            ring_ptr: sq_ring_ptr,
        };
        let cq = CompleteSeq {
            head: (cq_ring_ptr + (params.cq_off.head as *const u32 as usize)) as *mut u32,
            tail: (cq_ring_ptr + (params.cq_off.tail as *const u32 as usize)) as *mut u32,
            ring_mask: (cq_ring_ptr + (params.cq_off.ring_mask as *const u32 as usize)) as *mut u32,
            ring_entries: (cq_ring_ptr + (params.cq_off.ring_entries as *const u32 as usize)) as *mut u32,
            overflow: (cq_ring_ptr + (params.cq_off.overflow as *const u32 as usize)) as *mut u32,
            cqes: (cq_ring_ptr + (params.cq_off.cqes as *const u32 as usize)) as *mut nc::io_uring_cqe_t,
            ring_size: cq_ring_size,
            ring_ptr: cq_ring_ptr,
        };

        Ok(Uring{
            fd,
            params,
            sq_ring_ptr,
            sq_ring_size,
            sq,
            cq_ring_ptr,
            cq_ring_size,
            cq,
            sqes,
            sqes_size,
        })
    }

    fn flush_sq(&mut self) -> Result<u32> {
        if self.sq.sqe_head == self.sq.sqe_tail {
            println!("sqe head == sqe_tail: {}", self.sq.sqe_tail);
            return Ok(unsafe {*self.sq.tail - *self.sq.head});
        }

        // Fill in sqes that we have queued up, adding them to the kernel ring
        let mask = unsafe {*self.sq.ring_mask};
        let mut ktail: u32 = unsafe {*self.sq.tail};
        let mut to_submit: u32 = self.sq.sqe_tail - self.sq.sqe_head;
        for _i in 0..to_submit {
            // *(self.sq.array + (ktail & mask) as usize as  *u32) = (self.sq.sqe_head & mask as u32);
            ktail += 1;
            self.sq.sqe_head += 1;
        }

        let khead = unsafe {*self.sq.head};
        Ok(ktail - khead)
    }

    pub fn submit(&mut self) -> Result<u32> {
        let to_submit = self.flush_sq()?;
        println!("to_submit: {}", to_submit);
        let to_submit = 1;
        let nr_wait = 0;
        nc::io_uring_enter(self.fd, to_submit, nr_wait, 0, 0 as *const nc::sigset_t, 0)
    }

    pub fn get_sqe(&mut self) -> Result<*mut nc::io_uring_sqe_t> {
        // Get a submission queue from tail.
        let next = self.sq.sqe_tail + 1;
        let head = self.sq.sqe_head;
        let sqe: *mut nc::io_uring_sqe_t;
        if next - head <= unsafe{*self.sq.ring_entries} {
            let mask = unsafe {*self.sq.ring_mask};
            sqe = (self.sqes + ((self.sq.sqe_tail & mask) as usize)) as *mut nc::io_uring_sqe_t;
            self.sq.sqe_tail = next;
            println!("got new sqe!");
            return Ok(sqe);
        } else {
            return Err(nc::ERANGE);
        }
    }

    pub fn exit(&mut self) -> Result<()> {
        nc::munmap(self.sqes, self.sqes_size)?;
        nc::munmap(self.sq_ring_ptr, self.sq_ring_size)?;
        nc::munmap(self.cq_ring_ptr, self.cq_ring_size)?;
        Ok(())
    }

    fn get_cqe(&mut self, mut to_submit: u32, mut wait_nr: u32) -> Result<usize> {
        let sigmask = 0 as *const nc::sigset_t;
        let mut cqe: usize = 0;
        loop {
            let mut flags: u32 = 0;

            cqe = self.do_peek_cqe()?;

            if wait_nr > 0 {
                flags |= nc::IORING_ENTER_GETEVENTS;
            }

            if to_submit > 0 {

            }

            if wait_nr > 0 || to_submit > 0 {
               let ret =  nc::io_uring_enter(self.fd, to_submit, wait_nr, flags, sigmask, 0)?;
                if ret == to_submit {
                    to_submit = 0;
                    wait_nr = 0;
                } else {
                    to_submit = ret;
                }
            }

            if cqe as usize > 0 {
                break;
            }
        }

        Ok(cqe)
    }

    fn do_peek_cqe(&mut self) -> Result<usize> {
        let mut cqe: usize = 0;
        loop {
            if cqe > 0 {

            }
            break;
        }
        Ok(cqe)
    }

    pub fn get_cqe_nr(&mut self, wait_nr: u32) -> Result<*mut nc::io_uring_cqe_t> {
        self.do_peek_cqe()?;
        let cqe = self.get_cqe(0, wait_nr)?;
        Ok(cqe as *mut nc::io_uring_cqe_t)
    }

    pub fn wait_cqe(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn peek_cqe(&mut self) -> Result<()> {
        self.get_cqe_nr(0).map(drop)
    }
}

fn get_file_size(fd: i32) -> Result<nc::size_t> {
    let mut stat = nc::stat_t::default();
    nc::fstat(fd, &mut stat)?;
    Ok(stat.st_size as nc::size_t)
}

fn queue_prepped(uring: &mut Uring, ring_buf: &mut IoVecBuffer, fd: i32) -> Result<()> {
    let sqe: *mut nc::io_uring_sqe_t = uring.get_sqe()?;

    unsafe {
        (*sqe).opcode = nc::IOURING_OP::IORING_OP_READV;
        (*sqe).fd = fd;
        (*sqe).file_off.off = ring_buf.offset as u64;
        (*sqe).buf_addr.addr = &ring_buf.iov as *const nc::iovec_t as usize as u64;
        (*sqe).len = 1;
        (*sqe).user_data = ring_buf as *mut IoVecBuffer as usize as u64;
    }

    Ok(())
}

fn queue_read(uring: &mut Uring, ring_buf: &mut IoVecBuffer, size: nc::size_t, offset: nc::size_t, fd: i32) -> Result<()> {
    ring_buf.read = true;
    ring_buf.offset = offset;
    ring_buf.iov.iov_len = size;

    queue_prepped(uring, ring_buf, fd)
}

fn queue_write(uring: &mut Uring, ring_buf: &mut IoVecBuffer, fd: i32) -> Result<()> {
    ring_buf.read = false;
    // TODO(Shaohua): Update other offset properties

    queue_prepped(uring, ring_buf, fd)?;
    uring.submit().map(drop)
}

fn copy_files(uring: &mut Uring, input_fd: i32, output_fd: i32) -> Result<()> {
    let input_size: nc::size_t = get_file_size(input_fd)?;

    let mut buffers = BufferArray::new(BUF_LEN);

    let mut insize = input_size;
    let mut write_left = insize;
    let mut writes = 0;
    let mut reads = 0;
    let mut offset = 0;

    while insize > 0 || write_left > 0 {
        let mut had_reads = reads;

        // Queue up as many reads as we can
        while insize > 0 {
            let mut this_size = insize;
            if reads + writes > QUEUE_SIZE {
                break;
            }
            if this_size > BUF_LEN {
                this_size = BUF_LEN;
            } else if this_size == 0 {
                break;
            }

            let data = buffers.acquire().unwrap();
            if queue_read(uring, data, this_size, offset, input_fd).is_err() {
                break;
            }

            insize -= this_size;
            offset += this_size;
            reads += 1;
        }

        if had_reads != reads {
            uring.submit()?;
        }

        // Queue is full at this point. Find at least one completion.
        let mut got_comp = 0;
        while write_left > 0 {
            let mut cqe;
            if got_comp == 0 {
                cqe = uring.wait_cqe()?;
                got_comp = 1;
            } else {
                // peek cqe
                break;
            }

            // let data = get_cqe_data();
        }

        // current_read = usize::min(insize - read_offset, BUF_LEN);
        // queue_read(uring, &mut ring_buf,current_read, read_offset, input_fd)?;
        // read_offset += current_read;
    }



    let req = nc::timespec_t {
        tv_sec: 3,
        tv_nsec: 0
    };
    let mut rem = nc::timespec_t::default();
    nc::nanosleep(&req, &mut rem);

    nc::fsync(output_fd)?;

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} input output", args[0]);
        return Err(nc::EINVAL);
    }

    let input = &args[1];
    let output = &args[2];

    let input_fd = nc::openat(0,input, nc::O_RDONLY, 0)?;
    let output_fd = nc::openat(0, output, nc::O_WRONLY | nc::O_CREAT | nc::O_TRUNC, 0644)?;

    let mut uring = Uring::setup(QUEUE_SIZE).unwrap();

    copy_files(&mut uring, input_fd, output_fd)?;

    uring.exit();

    nc::close(input_fd);
    nc::close(output_fd);

    Ok(())
}


/// This allows for 1024 file descriptors: if NR_OPEN is ever grown
/// beyond that you'll have to change this too. But 1024 fd's seem to be
/// enough even for such "real" unices like OSF/1, so hopefully this is
/// one limit that doesn't have to be changed [again].
///
/// Note that POSIX wants the FD_CLEAR(fd,fdsetp) defines to be in
/// <sys/time.h> (and thus <linux/time.h>) - but this is a more logical
/// place for them. Solved by having dummy defines in <sys/time.h>.

/// This macro may have been defined in <gnu/types.h>. But we always
/// use the one here.
pub const FD_SETSIZE: usize = 1024;

#[repr(C)]
pub struct fd_set_t {
	pub fds_bits[usize; FD_SETSIZE / (8 * size_of::<isize>())];
}

// Type of a signal handler.
// TODO(Shaohua):
//typedef void (*__kernel_sighandler_t)(int);

/// Type of a SYSV IPC key.
pub type key_t = i32;
pub type ernelmqd_t = i32;

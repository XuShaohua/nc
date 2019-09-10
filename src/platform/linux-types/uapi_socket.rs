/// Desired design of maximum size and alignment (see RFC2553)
/// Implementation specific max size
const K_SS_MAXSIZE: i32 = 128;

/* Implementation specific desired alignment */
//pub const _K_SS_ALIGNSIZE: i32 =(__alignof__ (struct sockaddr *))

pub type kernel_sa_family_t = u16;

#[repr(C)]
pub struct kernel_sockaddr_storage_t {
    /// address family
    pub ss_family: kernel_sa_family_t,
    /// Following field(s) are implementation specific
    /// space to achieve desired size,
    /// _SS_MAXSIZE value minus size of ss_family
    pub data: [u8; (K_SS_MAXSIZE - 2) as usize],
}
// TODO(Shaohua):
//__attribute__ ((aligned(_K_SS_ALIGNSIZE)));	/* force desired alignment */

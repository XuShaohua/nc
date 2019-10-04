use crate::types::signal::sigset_t;

#[repr(C)]
pub struct ucontext_t {
    pub uc_flags: usize,
    pub uc_link: *mut ucontext_t,
    pub uc_stack: stack_t,

    pub uc_sigmask: sigset_t,

    /// glibc has 1024-bit signal masks, ours are 64-bit
    /// Allow for uc_sigmask growth
    pub unused: [sigset_t; 15],

    /// last for extensibility
    pub uc_mcontext: sigcontext_t,
}

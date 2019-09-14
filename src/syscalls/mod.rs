#[cfg(not(nightly))]
extern "C" {
    #[inline]
    pub fn __syscall0(n: usize) -> usize;

    #[inline]
    pub fn __syscall1(n: usize, a1: usize) -> usize;

    #[inline]
    pub fn __syscall2(n: usize, a1: usize, a2: usize) -> usize;

    #[inline]
    pub fn __syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize;

    #[inline]
    pub fn __syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize;

    #[inline]
    pub fn __syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize;

    #[inline]
    pub fn __syscall6(
        n: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
    ) -> usize;
}

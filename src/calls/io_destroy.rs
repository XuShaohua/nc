/// Destroy the `aio_context` specified.
///
/// May cancel any outstanding AIOs and block on completion.
///
/// Will fail with `-ENOSYS` if not implemented.
/// May fail with `-EINVAL` if the context pointed to is invalid.
pub unsafe fn io_destroy(ctx_id: aio_context_t) -> Result<(), Errno> {
    syscall1(SYS_IO_DESTROY, ctx_id).map(drop)
}

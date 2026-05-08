
Generate a shell script, save to `unwrap-syscalls.sh`:
1. Walk through `calls/` directory, to iterator over .rs files
2. find location (line number) of `syscallX()`, e.g. `syscall1()`, `syscall6()`
3. add `unsafe {` before location of `syscallX()`
4. add `}` after line of location of `syscalalX()` statement
5. rust `rustfmt` to format that .rs file
6. if that .rs file does not contain `syscallX()` pattern, log that filename and continue

two types of `syscallX()` pattern:
- inline mode, e.g. `syscall2(SYS___CLONE, flags, stack).map_err(drop) as i32` becomes `unsafe { syscall2(SYS___CLONE, flags, stack).map_err(drop) as i32 }`
- block mode: e.g.
```rust
syscall5(
    SYS_ADD_KEY,
    type_ptr,
    description_ptr,
    payload,
    plen,
    dest_keyring,
)
.map(|ret| ret as key_serial_t)
```
becomes:
```rust
unsafe {
    syscall5(
        SYS_ADD_KEY,
        type_ptr,
        description_ptr,
        payload,
        plen,
        dest_keyring,
    )
    .map(|ret| ret as key_serial_t)
}
```

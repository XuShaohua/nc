// From musl v1.2.5
.global __restore_rt
.hidden __restore_rt
.type __restore_rt,@function
__restore_rt:
    mov rax, 0xf
	syscall
.size __restore_rt,.-__restore_rt

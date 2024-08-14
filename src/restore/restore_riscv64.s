// From musl v1.2.5
.global __restore_rt
.type __restore_rt, %function
__restore_rt:
	li a7, 139
	ecall

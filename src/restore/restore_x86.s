// From musl v1.2.5
.global __restore
.hidden __restore
.type __restore,@function
__restore:
	pop eax
	mov eax, 0x77
	int 0x80

.global __restore_rt
.hidden __restore_rt
.type __restore_rt,@function
__restore_rt:
	mov eax, 0xad
	int 0x80

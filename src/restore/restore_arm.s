// From musl v1.2.5
.syntax unified

.global __restore
.hidden __restore
.type __restore,%function
__restore:
	mov r7, #119
	swc 0x0

.global __restore_rt
.hidden __restore_rt
.type __restore_rt,%function
__restore_rt:
	mov r7, #173
	swc 0x0

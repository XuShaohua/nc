
use super::types::*;

#[repr(C)]
pub union sigval_t {
	sival_int: i32,
	sival_ptr: usize,
}

pub const SI_MAX_SIZE: usize =	128;

/// The default "si_band" type is "long", as specified by POSIX.
/// However, some architectures want to override this to "int"
/// for historical compatibility reasons, so we allow that.
pub type __arch_si_band_t =  long;

pub type  __arch_si_clock_t =  clock_t;


#[repr(C)]
pub union __sifields_t {
	/* kill() */
    _kill: struct {
		pub _pid: pid_t,	/* sender's pid */
		pub _uid: uid_t,	/* sender's uid */
    },

	/* POSIX.1b timers */
	_timer: struct {
		pub _tid: timer_t,	/* timer id */
		pub _overrun: i32,		/* overrun count */
		pub _sigval: sigval_t,	/* same as below */
		_sys_private: i32,       /* not to be passed to user */
	},

	/* POSIX.1b signals */
	_rt: struct {
		pub _pid: pid_t,	/* sender's pid */
		pub _uid:uid_t, 	/* sender's uid */
		pub _sigval: sigval_t,
	},

	/* SIGCHLD */
	pub _sigchld: struct {
		pub _pid: pid_t,	/* which child */
		pub _uid: uid_t,	/* sender's uid */
		pub _status:i32,		/* exit code */
		pub _utime: __arch_si_clock_t,
		pub _stime: __arch_si_clock_t,
	},

	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
//	struct {
//		void __user *_addr; /* faulting insn/memory ref. */
//#ifdef __ARCH_SI_TRAPNO
//		int _trapno;	/* TRAP # which caused the signal */
//#endif
//#ifdef __ia64__
//		int _imm;		/* immediate value for "break" */
//		unsigned int _flags;	/* see ia64 si_flags */
//		unsigned long _isr;	/* isr */
//#endif
//
//#define __ADDR_BND_PKEY_PAD  (__alignof__(void *) < sizeof(short) ? \
//			      sizeof(short) : __alignof__(void *))
//		union {
//			/*
//			 * used when si_code=BUS_MCEERR_AR or
//			 * used when si_code=BUS_MCEERR_AO
//			 */
//			short _addr_lsb; /* LSB of the reported address */
//			/* used when si_code=SEGV_BNDERR */
//			struct {
//				char _dummy_bnd[__ADDR_BND_PKEY_PAD];
//				void __user *_lower;
//				void __user *_upper;
//			} _addr_bnd;
//			/* used when si_code=SEGV_PKUERR */
//			struct {
//				char _dummy_pkey[__ADDR_BND_PKEY_PAD];
//				__u32 _pkey;
//			} _addr_pkey;
//		};
//	} _sigfault;


	/* SIGPOLL */
	pub _sigpoll: struct {
		pub _band: __arch_si_band_t,	/* POLL_IN, POLL_OUT, POLL_MSG */
		pub _fd: i32,
	},

	/* SIGSYS */
	pub _sigsys: struct {
		pub _call_addr: usize, /* calling user insn */
		pub _syscall: i32,,	/* triggering system call number */
		pub _arch: u32,	/* AUDIT_ARCH_* of syscall */
	}
}

// TODO(Shaohua): Move to arch specific types.
#[repr(C)]
pub struct __siginfo_t {				
	pub si_signo: i32,
	pub si_errno: i32,
	pub si_code: i32,
	pub _sifields: __sifields_t,
}
//struct __siginfo_t {				\
//	int si_signo;			\
//	int si_code;			\
//	int si_errno;			\
//	union __sifields _sifields;	\
//}

#[repr(C)]
pub union siginfo_t {
    pub siginfo: __siginfo_t,
    pub _si_pad: [u8; SI_MAX_SIZE/size_of::<i32>()];
}

/// How these fields are to be accessed.
//#define si_pid		_sifields._kill._pid
//#define si_uid		_sifields._kill._uid
//#define si_tid		_sifields._timer._tid
//#define si_overrun	_sifields._timer._overrun
//#define si_sys_private  _sifields._timer._sys_private
//#define si_status	_sifields._sigchld._status
//#define si_utime	_sifields._sigchld._utime
//#define si_stime	_sifields._sigchld._stime
//#define si_value	_sifields._rt._sigval
//#define si_int		_sifields._rt._sigval.sival_int
//#define si_ptr		_sifields._rt._sigval.sival_ptr
//#define si_addr		_sifields._sigfault._addr
//#ifdef __ARCH_SI_TRAPNO
//#define si_trapno	_sifields._sigfault._trapno
//#endif
//#define si_addr_lsb	_sifields._sigfault._addr_lsb
//#define si_lower	_sifields._sigfault._addr_bnd._lower
//#define si_upper	_sifields._sigfault._addr_bnd._upper
//#define si_pkey		_sifields._sigfault._addr_pkey._pkey
//#define si_band		_sifields._sigpoll._band
//#define si_fd		_sifields._sigpoll._fd
//#define si_call_addr	_sifields._sigsys._call_addr
//#define si_syscall	_sifields._sigsys._syscall
//#define si_arch		_sifields._sigsys._arch

/// si_code values
/// Digital reserves positive values for kernel-generated signals.
#define SI_USER		0		/* sent by kill, sigsend, raise */
#define SI_KERNEL	0x80		/* sent by the kernel from somewhere */
#define SI_QUEUE	-1		/* sent by sigqueue */
#define SI_TIMER	-2		/* sent by timer expiration */
#define SI_MESGQ	-3		/* sent by real time mesq state change */
#define SI_ASYNCIO	-4		/* sent by AIO completion */
#define SI_SIGIO	-5		/* sent by queued SIGIO */
#define SI_TKILL	-6		/* sent by tkill system call */
#define SI_DETHREAD	-7		/* sent by execve() killing subsidiary threads */
#define SI_ASYNCNL	-60		/* sent by glibc async name lookup completion */

//#define SI_FROMUSER(siptr)	((siptr)->si_code <= 0)
//#define SI_FROMKERNEL(siptr)	((siptr)->si_code > 0)

/// SIGILL si_codes
#define ILL_ILLOPC	1	/* illegal opcode */
#define ILL_ILLOPN	2	/* illegal operand */
#define ILL_ILLADR	3	/* illegal addressing mode */
#define ILL_ILLTRP	4	/* illegal trap */
#define ILL_PRVOPC	5	/* privileged opcode */
#define ILL_PRVREG	6	/* privileged register */
#define ILL_COPROC	7	/* coprocessor error */
#define ILL_BADSTK	8	/* internal stack error */
#define ILL_BADIADDR	9	/* unimplemented instruction address */
#define __ILL_BREAK	10	/* illegal break */
#define __ILL_BNDMOD	11	/* bundle-update (modification) in progress */
#define NSIGILL		11

/// SIGFPE si_codes
#define FPE_INTDIV	1	/* integer divide by zero */
#define FPE_INTOVF	2	/* integer overflow */
#define FPE_FLTDIV	3	/* floating point divide by zero */
#define FPE_FLTOVF	4	/* floating point overflow */
#define FPE_FLTUND	5	/* floating point underflow */
#define FPE_FLTRES	6	/* floating point inexact result */
#define FPE_FLTINV	7	/* floating point invalid operation */
#define FPE_FLTSUB	8	/* subscript out of range */
#define __FPE_DECOVF	9	/* decimal overflow */
#define __FPE_DECDIV	10	/* decimal division by zero */
#define __FPE_DECERR	11	/* packed decimal error */
#define __FPE_INVASC	12	/* invalid ASCII digit */
#define __FPE_INVDEC	13	/* invalid decimal digit */
#define FPE_FLTUNK	14	/* undiagnosed floating-point exception */
#define FPE_CONDTRAP	15	/* trap on condition */
#define NSIGFPE		15

/// SIGSEGV si_codes
#define SEGV_MAPERR	1	/* address not mapped to object */
#define SEGV_ACCERR	2	/* invalid permissions for mapped object */
#define SEGV_BNDERR	3	/* failed address bound checks */
#ifdef __ia64__
# define __SEGV_PSTKOVF	4	/* paragraph stack overflow */
#else
# define SEGV_PKUERR	4	/* failed protection key checks */
#endif
#define SEGV_ACCADI	5	/* ADI not enabled for mapped object */
#define SEGV_ADIDERR	6	/* Disrupting MCD error */
#define SEGV_ADIPERR	7	/* Precise MCD exception */
#define NSIGSEGV	7

/// SIGBUS si_codes
#define BUS_ADRALN	1	/* invalid address alignment */
#define BUS_ADRERR	2	/* non-existent physical address */
#define BUS_OBJERR	3	/* object specific hardware error */
/* hardware memory error consumed on a machine check: action required */
#define BUS_MCEERR_AR	4
/* hardware memory error detected in process but not consumed: action optional*/
#define BUS_MCEERR_AO	5
#define NSIGBUS		5

/// SIGTRAP si_codes
#define TRAP_BRKPT	1	/* process breakpoint */
#define TRAP_TRACE	2	/* process trace trap */
#define TRAP_BRANCH     3	/* process taken branch trap */
#define TRAP_HWBKPT     4	/* hardware breakpoint/watchpoint */
#define TRAP_UNK	5	/* undiagnosed trap */
#define NSIGTRAP	5

/*
 * There is an additional set of SIGTRAP si_codes used by ptrace
 * that are of the form: ((PTRACE_EVENT_XXX << 8) | SIGTRAP)
 */

/// SIGCHLD si_codes
/// child has exited 
pub const CLD_EXITED: i32 = 	1;
/// child was killed 
pub const CLD_KILLED: i32 =	2;
/// child terminated abnormally 
pub const CLD_DUMPED: i32 = 	3;
/// traced child has trapped 
pub const CLD_TRAPPED: i32 = 	4;
#define CLD_STOPPED	5	/* child has stopped */
#define CLD_CONTINUED	6	/* stopped child has continued */
#define NSIGCHLD	6

/// SIGPOLL (or any other signal without signal specific si_codes) si_codes
/// data input available 
pub const POLL_IN: i32 = 		1;
/// output buffers available 
pub const  POLL_OUT: i32 = 	2;
/// input message available 
pub const POLL_MSG: i32 = 	3;
/// i/o error 
pub const POLL_ERR: i32 = 	4;
/// high priority input available 
pub const POLL_PRI: i32 = 	5;
/// device disconnected 
pub const POLL_HUP: i32 = 	6;
pub const NSIGPOLL: i32 = 	6;

/// SIGSYS si_codes

/// seccomp triggered 
pub const SYS_SECCOMP: i32 =	1;
pub const NSIGSYS: i32 = 		1;

/// SIGEMT si_codes
/// tag overflow
pub const EMT_TAGOVF: i32 = 	1;
pub const NSIGEMT: i32 = 		1;

/// sigevent definitions
/// 
/// It seems likely that SIGEV_THREAD will have to be handled from 
/// userspace, libpthread transmuting it to SIGEV_SIGNAL, which the
/// thread manager then catches and does the appropriate nonsense.
/// However, everything is written out here so as to not get lost.

/// notify via signal
pub const SIGEV_SIGNAL: i32 = 	0;
/// other notification: meaningless 
pub const SIGEV_NONE: i32 = 	1; 
/// deliver via thread creation 
pub const SIGEV_THREAD: i32 = 	2;
/// deliver to thread 
pub const SIGEV_THREAD_ID: i32 = 4; 

/// This works because the alignment is ok on all current architectures
/// but we leave open this being overridden in the future
pub const __ARCH_SIGEV_PREAMBLE_SIZE: usize = 	(size_of::<i32>() * 2 + size_of::<sigval_t>());

pub const SIGEV_MAX_SIZE: usize = 	64;
pub const SIGEV_PAD_SIZE: usize = 	((SIGEV_MAX_SIZE - __ARCH_SIGEV_PREAMBLE_SIZE) / size_of::<i32>());

#[repr(C)]
pub struct sigevent_t {
	pub sigev_value: sigval_t,
	pub sigev_signo: i32,
	pupb sigev_notify: i32,
	pub _sigev_un: union {
		_pad: [i32; SIGEV_PAD_SIZE],
		 _tid: i32,

		//_sigev_thread: struct {
			//void (*_function)(sigval_t);
			//void *_attribute;	/* really pthread_attr_t */
		//},
	} 
}

//#define sigev_notify_function	_sigev_un._sigev_thread._function
//#define sigev_notify_attributes	_sigev_un._sigev_thread._attribute
//#define sigev_notify_thread_id	 _sigev_un._tid

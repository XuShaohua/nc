// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From `arch/arm/include/asm/ptrace.h`

pub const PTRACE_GETREGS: i32 = 12;
pub const PTRACE_SETREGS: i32 = 13;
pub const PTRACE_GETFPREGS: i32 = 14;
pub const PTRACE_SETFPREGS: i32 = 15;
/// PTRACE_ATTACH is 16
/// PTRACE_DETACH is 17
pub const PTRACE_GETWMMXREGS: i32 = 18;
pub const PTRACE_SETWMMXREGS: i32 = 19;
/// 20 is unused
pub const PTRACE_OLDSETOPTIONS: i32 = 21;
pub const PTRACE_GET_THREAD_AREA: i32 = 22;
pub const PTRACE_SET_SYSCALL: i32 = 23;
/// PTRACE_SYSCALL is 24
pub const PTRACE_GETCRUNCHREGS: i32 = 25;
pub const PTRACE_SETCRUNCHREGS: i32 = 26;
pub const PTRACE_GETVFPREGS: i32 = 27;
pub const PTRACE_SETVFPREGS: i32 = 28;
pub const PTRACE_GETHBPREGS: i32 = 29;
pub const PTRACE_SETHBPREGS: i32 = 30;
pub const PTRACE_GETFDPIC: i32 = 31;

pub const PTRACE_GETFDPIC_EXEC: i32 = 0;
pub const PTRACE_GETFDPIC_INTERP: i32 = 1;

/// PSR bits
/// Note on V7M there is no mode contained in the PSR
pub const USR26_MODE: usize = 0x00000000;
pub const FIQ26_MODE: usize = 0x00000001;
pub const IRQ26_MODE: usize = 0x00000002;
pub const SVC26_MODE: usize = 0x00000003;
/// Use 0 here to get code right that creates a userspace
/// or kernel space thread.
pub const USR_MODE: usize = 0x00000000;
pub const SVC_MODE: usize = 0x00000000;
pub const FIQ_MODE: usize = 0x00000011;
pub const IRQ_MODE: usize = 0x00000012;
pub const MON_MODE: usize = 0x00000016;
pub const ABT_MODE: usize = 0x00000017;
pub const HYP_MODE: usize = 0x0000001a;
pub const UND_MODE: usize = 0x0000001b;
pub const SYSTEM_MODE: usize = 0x0000001f;
pub const MODE32_BIT: usize = 0x00000010;
pub const MODE_MASK: usize = 0x0000001f;

/// >= V4T, but not V7M
pub const V4_PSR_T_BIT: usize = 0x00000020;
pub const V7M_PSR_T_BIT: usize = 0x01000000;
pub const PSR_T_BIT: usize = V7M_PSR_T_BIT;

/// >= V4, but not V7M
pub const PSR_F_BIT: usize = 0x00000040;
/// >= V4, but not V7M
pub const PSR_I_BIT: usize = 0x00000080;
/// >= V6, but not V7M
pub const PSR_A_BIT: usize = 0x00000100;
/// >= V6, but not V7M
pub const PSR_E_BIT: usize = 0x00000200;
/// >= V5J, but not V7M
pub const PSR_J_BIT: usize = 0x01000000;
/// >= V5E, including V7M
pub const PSR_Q_BIT: usize = 0x08000000;
pub const PSR_V_BIT: usize = 0x10000000;
pub const PSR_C_BIT: usize = 0x20000000;
pub const PSR_Z_BIT: usize = 0x40000000;
pub const PSR_N_BIT: usize = 0x80000000;

/// Groups of PSR bits
/// Flags
pub const PSR_F: usize = 0xff000000;
/// Status
pub const PSR_S: usize = 0x00ff0000;
/// Extension
pub const PSR_X: usize = 0x0000ff00;
/// Control
pub const PSR_C: usize = 0x000000ff;

/// ARMv7 groups of PSR bits
/// N, Z, C, V, Q and GE flags
pub const APSR_MASK: usize = 0xf80f0000;
/// ISA state (J, T) mask
pub const PSR_ISET_MASK: usize = 0x01000010;
/// If-Then execution state mask
pub const PSR_IT_MASK: usize = 0x0600fc00;
/// Endianness state mask
pub const PSR_ENDIAN_MASK: usize = 0x00000200;

/// Default endianness state
#[cfg(target_endian = "big")]
pub const PSR_ENDSTATE: i32 = PSR_E_BIT;
#[cfg(not(target_endian = "big"))]
pub const PSR_ENDSTATE: i32 = 0;

/// These are 'magic' values for PTRACE_PEEKUSR that return info about where a
/// process is located in memory.
pub const PT_TEXT_ADDR: i32 = 0x10000;
pub const PT_DATA_ADDR: i32 = 0x10004;
pub const PT_TEXT_END_ADDR: i32 = 0x10008;

/// This struct defines the way the registers are stored on the
/// stack during a system call.  Note that sizeof(struct pt_regs)
/// has to be a multiple of 8.
#[repr(C)]
pub struct pt_regs_t {
    pub uregs: [usize; 18],
}

impl pt_regs_t {
    pub fn ARM_cpsr(&self) -> usize {
        self.uregs[16]
    }
    pub fn ARM_pc(&self) -> usize {
        self.uregs[15]
    }
    pub fn ARM_lr(&self) -> usize {
        self.uregs[14]
    }
    pub fn ARM_sp(&self) -> usize {
        self.uregs[13]
    }
    pub fn ARM_ip(&self) -> usize {
        self.uregs[12]
    }
    pub fn ARM_fp(&self) -> usize {
        self.uregs[11]
    }
    pub fn ARM_r10(&self) -> usize {
        self.uregs[10]
    }
    pub fn ARM_r9(&self) -> usize {
        self.uregs[9]
    }
    pub fn ARM_r8(&self) -> usize {
        self.uregs[8]
    }
    pub fn ARM_r7(&self) -> usize {
        self.uregs[7]
    }
    pub fn ARM_r6(&self) -> usize {
        self.uregs[6]
    }
    pub fn ARM_r5(&self) -> usize {
        self.uregs[5]
    }
    pub fn ARM_r4(&self) -> usize {
        self.uregs[4]
    }
    pub fn ARM_r3(&self) -> usize {
        self.uregs[3]
    }
    pub fn ARM_r2(&self) -> usize {
        self.uregs[2]
    }
    pub fn ARM_r1(&self) -> usize {
        self.uregs[1]
    }
    pub fn ARM_r0(&self) -> usize {
        self.uregs[0]
    }
    pub fn ARM_ORIG_r0(&self) -> usize {
        self.uregs[17]
    }
}

/// The size of the user-visible VFP state as seen by PTRACE_GET/SETVFPREGS
/// and core dumps.
pub const ARM_VFPREGS_SIZE: usize =  32 * 8 /*fpregs*/ + 4 /*fpscr*/ ;

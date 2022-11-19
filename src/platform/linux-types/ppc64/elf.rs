// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `arch/powerpc/include/uapi/asm/elf.h`
//!
/// ELF register definitions..

/// PowerPC relocations defined by the ABIs
pub const R_PPC_NONE: i32 = 0;
/// 32bit absolute address
pub const R_PPC_ADDR32: i32 = 1;
/// 26bit address, 2 bits ignored.
pub const R_PPC_ADDR24: i32 = 2;
/// 16bit absolute address
pub const R_PPC_ADDR16: i32 = 3;
/// lower 16bit of absolute address
pub const R_PPC_ADDR16_LO: i32 = 4;
/// high 16bit of absolute address
pub const R_PPC_ADDR16_HI: i32 = 5;
/// adjusted high 16bit
pub const R_PPC_ADDR16_HA: i32 = 6;
/// 16bit address, 2 bits ignored
pub const R_PPC_ADDR14: i32 = 7;
pub const R_PPC_ADDR14_BRTAKEN: i32 = 8;
pub const R_PPC_ADDR14_BRNTAKEN: i32 = 9;
/// PC relative 26 bit
pub const R_PPC_REL24: i32 = 10;
/// PC relative 16 bit
pub const R_PPC_REL14: i32 = 11;
pub const R_PPC_REL14_BRTAKEN: i32 = 12;
pub const R_PPC_REL14_BRNTAKEN: i32 = 13;
pub const R_PPC_GOT16: i32 = 14;
pub const R_PPC_GOT16_LO: i32 = 15;
pub const R_PPC_GOT16_HI: i32 = 16;
pub const R_PPC_GOT16_HA: i32 = 17;
pub const R_PPC_PLTREL24: i32 = 18;
pub const R_PPC_COPY: i32 = 19;
pub const R_PPC_GLOB_DAT: i32 = 20;
pub const R_PPC_JMP_SLOT: i32 = 21;
pub const R_PPC_RELATIVE: i32 = 22;
pub const R_PPC_LOCAL24PC: i32 = 23;
pub const R_PPC_UADDR32: i32 = 24;
pub const R_PPC_UADDR16: i32 = 25;
pub const R_PPC_REL32: i32 = 26;
pub const R_PPC_PLT32: i32 = 27;
pub const R_PPC_PLTREL32: i32 = 28;
pub const R_PPC_PLT16_LO: i32 = 29;
pub const R_PPC_PLT16_HI: i32 = 30;
pub const R_PPC_PLT16_HA: i32 = 31;
pub const R_PPC_SDAREL16: i32 = 32;
pub const R_PPC_SECTOFF: i32 = 33;
pub const R_PPC_SECTOFF_LO: i32 = 34;
pub const R_PPC_SECTOFF_HI: i32 = 35;
pub const R_PPC_SECTOFF_HA: i32 = 36;

/// PowerPC relocations defined for the TLS access ABI.
/// none	(sym+add)@tls
pub const R_PPC_TLS: i32 = 67;
/// word32	(sym+add)@dtpmod
pub const R_PPC_DTPMOD32: i32 = 68;
/// half16*	(sym+add)@tprel
pub const R_PPC_TPREL16: i32 = 69;
/// half16	(sym+add)@tprel@l
pub const R_PPC_TPREL16_LO: i32 = 70;
/// half16	(sym+add)@tprel@h
pub const R_PPC_TPREL16_HI: i32 = 71;
/// half16	(sym+add)@tprel@ha
pub const R_PPC_TPREL16_HA: i32 = 72;
/// word32	(sym+add)@tprel
pub const R_PPC_TPREL32: i32 = 73;
/// half16*	(sym+add)@dtprel
pub const R_PPC_DTPREL16: i32 = 74;
/// half16	(sym+add)@dtprel@l
pub const R_PPC_DTPREL16_LO: i32 = 75;
/// half16	(sym+add)@dtprel@h
pub const R_PPC_DTPREL16_HI: i32 = 76;
/// half16	(sym+add)@dtprel@ha
pub const R_PPC_DTPREL16_HA: i32 = 77;
/// word32	(sym+add)@dtprel
pub const R_PPC_DTPREL32: i32 = 78;
/// half16*	(sym+add)@got@tlsgd
pub const R_PPC_GOT_TLSGD16: i32 = 79;
/// half16	(sym+add)@got@tlsgd@l
pub const R_PPC_GOT_TLSGD16_LO: i32 = 80;
/// half16	(sym+add)@got@tlsgd@h
pub const R_PPC_GOT_TLSGD16_HI: i32 = 81;
/// half16	(sym+add)@got@tlsgd@ha
pub const R_PPC_GOT_TLSGD16_HA: i32 = 82;
/// half16*	(sym+add)@got@tlsld
pub const R_PPC_GOT_TLSLD16: i32 = 83;
/// half16	(sym+add)@got@tlsld@l
pub const R_PPC_GOT_TLSLD16_LO: i32 = 84;
/// half16	(sym+add)@got@tlsld@h
pub const R_PPC_GOT_TLSLD16_HI: i32 = 85;
/// half16	(sym+add)@got@tlsld@ha
pub const R_PPC_GOT_TLSLD16_HA: i32 = 86;
/// half16*	(sym+add)@got@tprel
pub const R_PPC_GOT_TPREL16: i32 = 87;
/// half16	(sym+add)@got@tprel@l
pub const R_PPC_GOT_TPREL16_LO: i32 = 88;
/// half16	(sym+add)@got@tprel@h
pub const R_PPC_GOT_TPREL16_HI: i32 = 89;
/// half16	(sym+add)@got@tprel@ha
pub const R_PPC_GOT_TPREL16_HA: i32 = 90;
/// half16*	(sym+add)@got@dtprel
pub const R_PPC_GOT_DTPREL16: i32 = 91;
/// half16*	(sym+add)@got@dtprel@l
pub const R_PPC_GOT_DTPREL16_LO: i32 = 92;
/// half16*	(sym+add)@got@dtprel@h
pub const R_PPC_GOT_DTPREL16_HI: i32 = 93;
/// half16*	(sym+add)@got@dtprel@ha
pub const R_PPC_GOT_DTPREL16_HA: i32 = 94;

/// keep this the last entry.
pub const R_PPC_NUM: i32 = 95;


/// includes nip, msr, lr, etc.
pub const ELF_NGREG: i32 = 48;
/// includes fpscr
pub const ELF_NFPREG: i32 = 33;
/// includes all vector registers
pub const ELF_NVMX: i32 = 34;
/// includes all VSX registers
pub const ELF_NVSX: i32 = 32;
/// include tfhar, tfiar, texasr
pub const ELF_NTMSPRREG: i32 = 3;
/// includes ebbrr, ebbhr, bescr
pub const ELF_NEBB: i32 = 3;
/// includes siar, sdar, sier, mmcr2, mmcr0
pub const ELF_NPMU: i32 = 5;
/// includes amr, iamr, uamor
pub const ELF_NPKEY: i32 = 3;

pub type elf_greg_t64 = usize;
typedef elf_greg_t64 elf_gregset_t64[ELF_NGREG];

pub type elf_greg_t32 = u32;
typedef elf_greg_t32 elf_gregset_t32[ELF_NGREG];
typedef elf_gregset_t32 compat_elf_gregset_t;

/// ELF_ARCH, CLASS, and DATA are used to set parameters in the core dumps.
/// includes vscr & vrsave stuffed together 
pub const ELF_NVRREG32: i32=	33;
/// includes vscr & vrsave in split vectors
pub const ELF_NVRREG: i32 = 	34;
/// Half the vsx registers 
pub const ELF_NVSRHALFREG: i32 =  32;
pub type ELF_GREG_TYPE: = 	elf_greg_t64;
pub const ELF_ARCH: i32 = 	EM_PPC64;
pub const ELF_CLASS: i32 =	ELFCLASS64;
pub const elf_greg_t64: i32 = elf_greg_t;
typedef elf_gregset_t64 elf_gregset_t;

#ifdef __BIG_ENDIAN__
pub const ELF_DATA: i32 = ELFDATA2MSB;
#else
pub const ELF_DATA: i32 = ELFDATA2LSB;
#endif

/// Floating point registers
typedef double elf_fpreg_t;
typedef elf_fpreg_t elf_fpregset_t[ELF_NFPREG];

/// Altivec registers

/// The entries with indexes 0-31 contain the corresponding vector registers. 
/// The entry with index 32 contains the vscr as the last word (offset 12) 
/// within the quadword.  This allows the vscr to be stored as either a 
/// quadword (since it must be copied via a vector register to/from storage) 
/// or as a word.  
/// 
/// 64-bit kernel notes: The entry at index 33 contains the vrsave as the first  
/// word (offset 0) within the quadword.
/// 
/// This definition of the VMX state is compatible with the current PPC32 
/// ptrace interface.  This allows signal handling and ptrace to use the same 
/// structures.  This also simplifies the implementation of a bi-arch 
/// (combined (32- and 64-bit) gdb.
/// 
/// Note that it's _not_ compatible with 32 bits ucontext which stuffs the
/// vrsave along with vscr and so only uses 33 vectors for the register set
 
typedef __vector128 elf_vrreg_t;
typedef elf_vrreg_t elf_vrregset_t[ELF_NVRREG];
typedef elf_vrreg_t elf_vrregset_t32[ELF_NVRREG32];
typedef elf_fpreg_t elf_vsrreghalf_t32[ELF_NVSRHALFREG];

/// PowerPC64 relocations defined by the ABIs
pub const R_PPC64_NONE: i32 = R_PPC_NONE;
/// 32bit absolute address.
pub const R_PPC64_ADDR32: i32 = R_PPC_ADDR32;
/// 26bit address, word aligned.
pub const R_PPC64_ADDR24: i32 = R_PPC_ADDR24;
/// 16bit absolute address.
pub const R_PPC64_ADDR16: i32 = R_PPC_ADDR16;
/// lower 16bits of abs. address.
pub const R_PPC64_ADDR16_LO: i32 = R_PPC_ADDR16_LO;
/// high 16bits of abs. address.
pub const R_PPC64_ADDR16_HI: i32 = R_PPC_ADDR16_HI;
/// adjusted high 16bits.
pub const R_PPC64_ADDR16_HA: i32 = R_PPC_ADDR16_HA;
/// 16bit address, word aligned.
pub const R_PPC64_ADDR14: i32 = R_PPC_ADDR14;
pub const R_PPC64_ADDR14_BRTAKEN: i32 = R_PPC_ADDR14_BRTAKEN;
pub const R_PPC64_ADDR14_BRNTAKEN: i32 = R_PPC_ADDR14_BRNTAKEN;
/// PC relative 26 bit, word aligned.
pub const R_PPC64_REL24: i32 = R_PPC_REL24;
/// PC relative 16 bit.
pub const R_PPC64_REL14: i32 = R_PPC_REL14;
pub const R_PPC64_REL14_BRTAKEN: i32 = R_PPC_REL14_BRTAKEN;
pub const R_PPC64_REL14_BRNTAKEN: i32 = R_PPC_REL14_BRNTAKEN;
pub const R_PPC64_GOT16: i32 = R_PPC_GOT16;
pub const R_PPC64_GOT16_LO: i32 = R_PPC_GOT16_LO;
pub const R_PPC64_GOT16_HI: i32 = R_PPC_GOT16_HI;
pub const R_PPC64_GOT16_HA: i32 = R_PPC_GOT16_HA;

pub const R_PPC64_COPY: i32 = R_PPC_COPY;
pub const R_PPC64_GLOB_DAT: i32 = R_PPC_GLOB_DAT;
pub const R_PPC64_JMP_SLOT: i32 = R_PPC_JMP_SLOT;
pub const R_PPC64_RELATIVE: i32 = R_PPC_RELATIVE;

pub const R_PPC64_UADDR32: i32 = R_PPC_UADDR32;
pub const R_PPC64_UADDR16: i32 = R_PPC_UADDR16;
pub const R_PPC64_REL32: i32 = R_PPC_REL32;
pub const R_PPC64_PLT32: i32 = R_PPC_PLT32;
pub const R_PPC64_PLTREL32: i32 = R_PPC_PLTREL32;
pub const R_PPC64_PLT16_LO: i32 = R_PPC_PLT16_LO;
pub const R_PPC64_PLT16_HI: i32 = R_PPC_PLT16_HI;
pub const R_PPC64_PLT16_HA: i32 = R_PPC_PLT16_HA;

pub const R_PPC64_SECTOFF: i32 = R_PPC_SECTOFF;
pub const R_PPC64_SECTOFF_LO: i32 = R_PPC_SECTOFF_LO;
pub const R_PPC64_SECTOFF_HI: i32 = R_PPC_SECTOFF_HI;
pub const R_PPC64_SECTOFF_HA: i32 = R_PPC_SECTOFF_HA;
/// word30 (S + A - P) >> 2.
pub const R_PPC64_ADDR30: i32 = 37;
/// doubleword64 S + A.
pub const R_PPC64_ADDR64: i32 = 38;
/// half16 #higher(S + A).
pub const R_PPC64_ADDR16_HIGHER: i32 = 39;
/// half16 #highera(S + A).
pub const R_PPC64_ADDR16_HIGHERA: i32 = 40;
/// half16 #highest(S + A).
pub const R_PPC64_ADDR16_HIGHEST: i32 = 41;
/// half16 #highesta(S + A).
pub const R_PPC64_ADDR16_HIGHESTA: i32 = 42;
/// doubleword64 S + A.
pub const R_PPC64_UADDR64: i32 = 43;
/// doubleword64 S + A - P.
pub const R_PPC64_REL64: i32 = 44;
/// doubleword64 L + A.
pub const R_PPC64_PLT64: i32 = 45;
/// doubleword64 L + A - P.
pub const R_PPC64_PLTREL64: i32 = 46;
/// half16* S + A - .TOC.
pub const R_PPC64_TOC16: i32 = 47;
/// half16 #lo(S + A - .TOC.).
pub const R_PPC64_TOC16_LO: i32 = 48;
/// half16 #hi(S + A - .TOC.).
pub const R_PPC64_TOC16_HI: i32 = 49;
/// half16 #ha(S + A - .TOC.).
pub const R_PPC64_TOC16_HA: i32 = 50;
/// doubleword64 .TOC.
pub const R_PPC64_TOC: i32 = 51;
/// half16* M + A.
pub const R_PPC64_PLTGOT16: i32 = 52;
/// half16 #lo(M + A).
pub const R_PPC64_PLTGOT16_LO: i32 = 53;
/// half16 #hi(M + A).
pub const R_PPC64_PLTGOT16_HI: i32 = 54;
/// half16 #ha(M + A).
pub const R_PPC64_PLTGOT16_HA: i32 = 55;

/// half16ds* (S + A) >> 2.
pub const R_PPC64_ADDR16_DS: i32 = 56;
/// half16ds  #lo(S + A) >> 2.
pub const R_PPC64_ADDR16_LO_DS: i32 = 57;
/// half16ds* (G + A) >> 2.
pub const R_PPC64_GOT16_DS: i32 = 58;
/// half16ds  #lo(G + A) >> 2.
pub const R_PPC64_GOT16_LO_DS: i32 = 59;
/// half16ds  #lo(L + A) >> 2.
pub const R_PPC64_PLT16_LO_DS: i32 = 60;
/// half16ds* (R + A) >> 2.
pub const R_PPC64_SECTOFF_DS: i32 = 61;
/// half16ds  #lo(R + A) >> 2.
pub const R_PPC64_SECTOFF_LO_DS: i32 = 62;
/// half16ds* (S + A - .TOC.) >> 2.
pub const R_PPC64_TOC16_DS: i32 = 63;
/// half16ds  #lo(S + A - .TOC.) >> 2.
pub const R_PPC64_TOC16_LO_DS: i32 = 64;
/// half16ds* (M + A) >> 2.
pub const R_PPC64_PLTGOT16_DS: i32 = 65;
/// half16ds  #lo(M + A) >> 2.
pub const R_PPC64_PLTGOT16_LO_DS: i32 = 66;

/// PowerPC64 relocations defined for the TLS access ABI.
/// none	(sym+add)@tls
pub const R_PPC64_TLS: i32 = 67;
/// doubleword64 (sym+add)@dtpmod
pub const R_PPC64_DTPMOD64: i32 = 68;
/// half16*	(sym+add)@tprel
pub const R_PPC64_TPREL16: i32 = 69;
/// half16	(sym+add)@tprel@l
pub const R_PPC64_TPREL16_LO: i32 = 70;
/// half16	(sym+add)@tprel@h
pub const R_PPC64_TPREL16_HI: i32 = 71;
/// half16	(sym+add)@tprel@ha
pub const R_PPC64_TPREL16_HA: i32 = 72;
/// doubleword64 (sym+add)@tprel
pub const R_PPC64_TPREL64: i32 = 73;
/// half16*	(sym+add)@dtprel
pub const R_PPC64_DTPREL16: i32 = 74;
/// half16	(sym+add)@dtprel@l
pub const R_PPC64_DTPREL16_LO: i32 = 75;
/// half16	(sym+add)@dtprel@h
pub const R_PPC64_DTPREL16_HI: i32 = 76;
/// half16	(sym+add)@dtprel@ha
pub const R_PPC64_DTPREL16_HA: i32 = 77;
/// doubleword64 (sym+add)@dtprel
pub const R_PPC64_DTPREL64: i32 = 78;
/// half16*	(sym+add)@got@tlsgd
pub const R_PPC64_GOT_TLSGD16: i32 = 79;
/// half16	(sym+add)@got@tlsgd@l
pub const R_PPC64_GOT_TLSGD16_LO: i32 = 80;
/// half16	(sym+add)@got@tlsgd@h
pub const R_PPC64_GOT_TLSGD16_HI: i32 = 81;
/// half16	(sym+add)@got@tlsgd@ha
pub const R_PPC64_GOT_TLSGD16_HA: i32 = 82;
/// half16*	(sym+add)@got@tlsld
pub const R_PPC64_GOT_TLSLD16: i32 = 83;
/// half16	(sym+add)@got@tlsld@l
pub const R_PPC64_GOT_TLSLD16_LO: i32 = 84;
/// half16	(sym+add)@got@tlsld@h
pub const R_PPC64_GOT_TLSLD16_HI: i32 = 85;
/// half16	(sym+add)@got@tlsld@ha
pub const R_PPC64_GOT_TLSLD16_HA: i32 = 86;
/// half16ds*	(sym+add)@got@tprel
pub const R_PPC64_GOT_TPREL16_DS: i32 = 87;
/// half16ds (sym+add)@got@tprel@l
pub const R_PPC64_GOT_TPREL16_LO_DS: i32 = 88;
/// half16	(sym+add)@got@tprel@h
pub const R_PPC64_GOT_TPREL16_HI: i32 = 89;
/// half16	(sym+add)@got@tprel@ha
pub const R_PPC64_GOT_TPREL16_HA: i32 = 90;
/// half16ds*	(sym+add)@got@dtprel
pub const R_PPC64_GOT_DTPREL16_DS: i32 = 91;
/// half16ds (sym+add)@got@dtprel@l
pub const R_PPC64_GOT_DTPREL16_LO_DS: i32 = 92;
/// half16	(sym+add)@got@dtprel@h
pub const R_PPC64_GOT_DTPREL16_HI: i32 = 93;
/// half16	(sym+add)@got@dtprel@ha
pub const R_PPC64_GOT_DTPREL16_HA: i32 = 94;
/// half16ds*	(sym+add)@tprel
pub const R_PPC64_TPREL16_DS: i32 = 95;
/// half16ds	(sym+add)@tprel@l
pub const R_PPC64_TPREL16_LO_DS: i32 = 96;
/// half16	(sym+add)@tprel@higher
pub const R_PPC64_TPREL16_HIGHER: i32 = 97;
/// half16	(sym+add)@tprel@highera
pub const R_PPC64_TPREL16_HIGHERA: i32 = 98;
/// half16	(sym+add)@tprel@highest
pub const R_PPC64_TPREL16_HIGHEST: i32 = 99;
/// half16	(sym+add)@tprel@highesta
pub const R_PPC64_TPREL16_HIGHESTA: i32 = 100;
/// half16ds* (sym+add)@dtprel
pub const R_PPC64_DTPREL16_DS: i32 = 101;
/// half16ds	(sym+add)@dtprel@l
pub const R_PPC64_DTPREL16_LO_DS: i32 = 102;
/// half16	(sym+add)@dtprel@higher
pub const R_PPC64_DTPREL16_HIGHER: i32 = 103;
/// half16	(sym+add)@dtprel@highera
pub const R_PPC64_DTPREL16_HIGHERA: i32 = 104;
/// half16	(sym+add)@dtprel@highest
pub const R_PPC64_DTPREL16_HIGHEST: i32 = 105;
/// half16	(sym+add)@dtprel@highesta
pub const R_PPC64_DTPREL16_HIGHESTA: i32 = 106;
pub const R_PPC64_TLSGD: i32 = 107;
pub const R_PPC64_TLSLD: i32 = 108;
pub const R_PPC64_TOCSAVE: i32 = 109;

pub const R_PPC64_ENTRY: i32 = 118;

pub const R_PPC64_REL16: i32 = 249;
pub const R_PPC64_REL16_LO: i32 = 250;
pub const R_PPC64_REL16_HI: i32 = 251;
pub const R_PPC64_REL16_HA: i32 = 252;

/// Keep this the last entry.
pub const R_PPC64_NUM: i32 = 253;

/// There's actually a third entry here, but it's unused
#[repr(C)]
pub struct ppc64_opd_entry_t {
	pub funcaddr: usize,
	pub r2: usize,
}


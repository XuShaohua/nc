// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::types::*;

/// Extended instruction set based on top of classic BPF

/// instruction classes
/// jmp mode in word width
pub const BPF_JMP32: i32 = 0x06;
/// alu mode in double word width
pub const BPF_ALU64: i32 = 0x07;

/// ld/ldx fields
/// double word (64-bit)
pub const BPF_DW: i32 = 0x18;
/// exclusive add
pub const BPF_XADD: i32 = 0xc0;

/// alu/jmp fields
/// mov reg to reg
pub const BPF_MOV: i32 = 0xb0;
/// sign extending arithmetic shift right
pub const BPF_ARSH: i32 = 0xc0;

/// change endianness of a register
/// flags for endianness conversion:
pub const BPF_END: i32 = 0xd0;
/// convert to little-endian
pub const BPF_TO_LE: i32 = 0x00;
/// convert to big-endian
pub const BPF_TO_BE: i32 = 0x08;
pub const BPF_FROM_LE: i32 = BPF_TO_LE;
pub const BPF_FROM_BE: i32 = BPF_TO_BE;

/// jmp encodings
/// jump !=
pub const BPF_JNE: i32 = 0x50;
/// LT is unsigned, '<'
pub const BPF_JLT: i32 = 0xa0;
/// LE is unsigned, '<='
pub const BPF_JLE: i32 = 0xb0;
/// SGT is signed '>', GT in x86
pub const BPF_JSGT: i32 = 0x60;
/// SGE is signed '>=', GE in x86
pub const BPF_JSGE: i32 = 0x70;
/// SLT is signed, '<'
pub const BPF_JSLT: i32 = 0xc0;
/// SLE is signed, '<='
pub const BPF_JSLE: i32 = 0xd0;
/// function call
pub const BPF_CALL: i32 = 0x80;
/// function return
pub const BPF_EXIT: i32 = 0x90;

/// Register numbers
pub const BPF_REG_0: i32 = 0;
pub const BPF_REG_1: i32 = 1;
pub const BPF_REG_2: i32 = 2;
pub const BPF_REG_3: i32 = 3;
pub const BPF_REG_4: i32 = 4;
pub const BPF_REG_5: i32 = 5;
pub const BPF_REG_6: i32 = 6;
pub const BPF_REG_7: i32 = 7;
pub const BPF_REG_8: i32 = 8;
pub const BPF_REG_9: i32 = 9;
pub const BPF_REG_10: i32 = 10;
/// BPF has 10 general purpose 64-bit registers and stack frame.
pub const MAX_BPF_REG: i32 = BPF_REG_10 + 1;

#[repr(C)]
pub struct bpf_insn_t {
    /// opcode
    pub code: u8,
    //__u8	dst_reg:4;	/* dest register */
    //__u8	src_reg:4;	/* source register */
    /// dest register
    pub dst_reg: u32,
    /// source register/
    pub src_reg: u32,
    /// signed offset
    pub off: i16,
    /// signed immediate constant
    pub imm: i32,
}

/// Key of an a BPF_MAP_TYPE_LPM_TRIE entry
#[repr(C)]
pub struct bpf_lpm_trie_key_t {
    /// up to 32 for AF_INET, 128 for AF_INET6
    pub prefixlen: u32,
    /// Arbitrary size
    pub data: [u8; 0],
}

#[repr(C)]
pub struct bpf_cgroup_storage_key_t {
    /// cgroup inode id
    pub cgroup_inode_id: u64,
    /// program attach type
    pub attach_type: u32,
}

/// BPF syscall commands, see bpf(2) man-page for details.
pub const BPF_MAP_CREATE: i32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_MAP_UPDATE_ELEM: i32 = 2;
pub const BPF_MAP_DELETE_ELEM: i32 = 3;
pub const BPF_MAP_GET_NEXT_KEY: i32 = 4;
pub const BPF_PROG_LOAD: i32 = 5;
pub const BPF_OBJ_PIN: i32 = 6;
pub const BPF_OBJ_GET: i32 = 7;
pub const BPF_PROG_ATTACH: i32 = 8;
pub const BPF_PROG_DETACH: i32 = 9;
pub const BPF_PROG_TEST_RUN: i32 = 10;
pub const BPF_PROG_GET_NEXT_ID: i32 = 11;
pub const BPF_MAP_GET_NEXT_ID: i32 = 12;
pub const BPF_PROG_GET_FD_BY_ID: i32 = 13;
pub const BPF_MAP_GET_FD_BY_ID: i32 = 14;
pub const BPF_OBJ_GET_INFO_BY_FD: i32 = 15;
pub const BPF_PROG_QUERY: i32 = 16;
pub const BPF_RAW_TRACEPOINT_OPEN: i32 = 17;
pub const BPF_BTF_LOAD: i32 = 18;
pub const BPF_BTF_GET_FD_BY_ID: i32 = 19;
pub const BPF_TASK_FD_QUERY: i32 = 20;
pub const BPF_MAP_LOOKUP_AND_DELETE_ELEM: i32 = 21;

pub const BPF_MAP_TYPE_UNSPEC: i32 = 0;
pub const BPF_MAP_TYPE_HASH: i32 = 1;
pub const BPF_MAP_TYPE_ARRAY: i32 = 2;
pub const BPF_MAP_TYPE_PROG_ARRAY: i32 = 3;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: i32 = 4;
pub const BPF_MAP_TYPE_PERCPU_HASH: i32 = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: i32 = 6;
pub const BPF_MAP_TYPE_STACK_TRACE: i32 = 7;
pub const BPF_MAP_TYPE_CGROUP_ARRAY: i32 = 8;
pub const BPF_MAP_TYPE_LRU_HASH: i32 = 9;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: i32 = 10;
pub const BPF_MAP_TYPE_LPM_TRIE: i32 = 11;
pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: i32 = 12;
pub const BPF_MAP_TYPE_HASH_OF_MAPS: i32 = 13;
pub const BPF_MAP_TYPE_DEVMAP: i32 = 14;
pub const BPF_MAP_TYPE_SOCKMAP: i32 = 15;
pub const BPF_MAP_TYPE_CPUMAP: i32 = 16;
pub const BPF_MAP_TYPE_XSKMAP: i32 = 17;
pub const BPF_MAP_TYPE_SOCKHASH: i32 = 18;
pub const BPF_MAP_TYPE_CGROUP_STORAGE: i32 = 19;
pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: i32 = 20;
pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: i32 = 21;
pub const BPF_MAP_TYPE_QUEUE: i32 = 22;
pub const BPF_MAP_TYPE_STACK: i32 = 23;

/// Note that tracing related programs such as
/// BPF_PROG_TYPE_{KPROBE,TRACEPOINT,PERF_EVENT,RAW_TRACEPOINT}
/// are not subject to a stable API since kernel internal data
/// structures can change from release to release and may
/// therefore break existing tracing BPF programs. Tracing BPF
/// programs correspond to /a/ specific kernel which is to be
/// analyzed, and not /a/ specific kernel /and/ all future ones.
pub const BPF_PROG_TYPE_UNSPEC: i32 = 0;
pub const BPF_PROG_TYPE_SOCKET_FILTER: i32 = 1;
pub const BPF_PROG_TYPE_KPROBE: i32 = 2;
pub const BPF_PROG_TYPE_SCHED_CLS: i32 = 3;
pub const BPF_PROG_TYPE_SCHED_ACT: i32 = 4;
pub const BPF_PROG_TYPE_TRACEPOINT: i32 = 5;
pub const BPF_PROG_TYPE_XDP: i32 = 6;
pub const BPF_PROG_TYPE_PERF_EVENT: i32 = 7;
pub const BPF_PROG_TYPE_CGROUP_SKB: i32 = 8;
pub const BPF_PROG_TYPE_CGROUP_SOCK: i32 = 9;
pub const BPF_PROG_TYPE_LWT_IN: i32 = 10;
pub const BPF_PROG_TYPE_LWT_OUT: i32 = 11;
pub const BPF_PROG_TYPE_LWT_XMIT: i32 = 12;
pub const BPF_PROG_TYPE_SOCK_OPS: i32 = 13;
pub const BPF_PROG_TYPE_SK_SKB: i32 = 14;
pub const BPF_PROG_TYPE_CGROUP_DEVICE: i32 = 15;
pub const BPF_PROG_TYPE_SK_MSG: i32 = 16;
pub const BPF_PROG_TYPE_RAW_TRACEPOINT: i32 = 17;
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: i32 = 18;
pub const BPF_PROG_TYPE_LWT_SEG6LOCAL: i32 = 19;
pub const BPF_PROG_TYPE_LIRC_MODE2: i32 = 20;
pub const BPF_PROG_TYPE_SK_REUSEPORT: i32 = 21;
pub const BPF_PROG_TYPE_FLOW_DISSECTOR: i32 = 22;

pub const BPF_CGROUP_INET_INGRESS: i32 = 0;
pub const BPF_CGROUP_INET_EGRESS: i32 = 1;
pub const BPF_CGROUP_INET_SOCK_CREATE: i32 = 2;
pub const BPF_CGROUP_SOCK_OPS: i32 = 3;
pub const BPF_SK_SKB_STREAM_PARSER: i32 = 4;
pub const BPF_SK_SKB_STREAM_VERDICT: i32 = 5;
pub const BPF_CGROUP_DEVICE: i32 = 6;
pub const BPF_SK_MSG_VERDICT: i32 = 7;
pub const BPF_CGROUP_INET4_BIND: i32 = 8;
pub const BPF_CGROUP_INET6_BIND: i32 = 9;
pub const BPF_CGROUP_INET4_CONNECT: i32 = 10;
pub const BPF_CGROUP_INET6_CONNECT: i32 = 11;
pub const BPF_CGROUP_INET4_POST_BIND: i32 = 12;
pub const BPF_CGROUP_INET6_POST_BIND: i32 = 13;
pub const BPF_CGROUP_UDP4_SENDMSG: i32 = 14;
pub const BPF_CGROUP_UDP6_SENDMSG: i32 = 15;
pub const BPF_LIRC_MODE2: i32 = 16;
pub const BPF_FLOW_DISSECTOR: i32 = 17;
pub const MAX_BPF_ATTACH_TYPE: i32 = BPF_FLOW_DISSECTOR + 1;

/// cgroup-bpf attach flags used in BPF_PROG_ATTACH command
///
/// NONE(default): No further bpf programs allowed in the subtree.
///
/// BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
/// the program in this cgroup yields to sub-cgroup program.
///
/// BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
/// that cgroup program gets run in addition to the program in this cgroup.
///
/// Only one program is allowed to be attached to a cgroup with
/// NONE or BPF_F_ALLOW_OVERRIDE flag.
/// Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
/// release old program and attach the new one. Attach flags has to match.
///
/// Multiple programs are allowed to be attached to a cgroup with
/// BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
/// (those that were attached first, run first)
/// The programs of sub-cgroup are executed first, then programs of
/// this cgroup and then programs of parent cgroup.
/// When children program makes decision (like picking TCP CA or sock bind)
/// parent program has a chance to override it.
///
/// A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
/// A cgroup with NONE doesn't allow any programs in sub-cgroups.
/// Ex1:
/// cgrp1 (MULTI progs A, B) ->
///    cgrp2 (OVERRIDE prog C) ->
///      cgrp3 (MULTI prog D) ->
///        cgrp4 (OVERRIDE prog E) ->
///          cgrp5 (NONE prog F)
/// the event in cgrp5 triggers execution of F,D,A,B in that order.
/// if prog F is detached, the execution is E,D,A,B
/// if prog F and D are detached, the execution is E,A,B
/// if prog F, E and D are detached, the execution is C,A,B
///
/// All eligible programs are executed regardless of return code from
/// earlier programs.
pub const BPF_F_ALLOW_OVERRIDE: i32 = 1 << 0;
pub const BPF_F_ALLOW_MULTI: i32 = 1 << 1;

/// If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
/// verifier will perform strict alignment checking as if the kernel
/// has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
/// and NET_IP_ALIGN defined to 2.
pub const BPF_F_STRICT_ALIGNMENT: i32 = 1 << 0;

/// If BPF_F_ANY_ALIGNMENT is used in BPF_PROF_LOAD command, the
/// verifier will allow any alignment whatsoever.  On platforms
/// with strict alignment requirements for loads ands stores (such
/// as sparc and mips) the verifier validates that all loads and
/// stores provably follow this requirement.  This flag turns that
/// checking and enforcement off.
///
/// It is mostly used for testing when we want to validate the
/// context and memory access aspects of the verifier, but because
/// of an unaligned access the alignment check would trigger before
/// the one we are interested in.
pub const BPF_F_ANY_ALIGNMENT: i32 = 1 << 1;

/// when bpf_ldimm64->src_reg == BPF_PSEUDO_MAP_FD, bpf_ldimm64->imm == fd
pub const BPF_PSEUDO_MAP_FD: i32 = 1;

/// when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
/// offset to another bpf function
pub const BPF_PSEUDO_CALL: i32 = 1;

/// flags for BPF_MAP_UPDATE_ELEM command
/// create new element or update existing
pub const BPF_ANY: i32 = 0;
/// create new element if it didn't exist
pub const BPF_NOEXIST: i32 = 1;
/// update existing element
pub const BPF_EXIST: i32 = 2;
/// spin_lock-ed map_lookup/map_update
pub const BPF_F_LOCK: i32 = 4;

/// flags for BPF_MAP_CREATE command
pub const BPF_F_NO_PREALLOC: i32 = 1 << 0;

/// Instead of having one common LRU list in the
/// BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
/// which can scale and perform better.
/// Note, the LRU nodes (including free nodes) cannot be moved
/// across different LRU lists.
pub const BPF_F_NO_COMMON_LRU: i32 = 1 << 1;

/// Specify numa node during map creation
pub const BPF_F_NUMA_NODE: i32 = 1 << 2;

pub const BPF_OBJ_NAME_LEN: usize = 16;

/// Flags for accessing BPF object
pub const BPF_F_RDONLY: i32 = 1 << 3;
pub const BPF_F_WRONLY: i32 = 1 << 4;

/// Flag for stack_map, store build_id+offset instead of pointer
pub const BPF_F_STACK_BUILD_ID: i32 = 1 << 5;

/// Zero-initialize hash function seed. This should only be used for testing.
pub const BPF_F_ZERO_SEED: i32 = 1 << 6;

/// flags for BPF_PROG_QUERY
pub const BPF_F_QUERY_EFFECTIVE: i32 = 1 << 0;

/// user space need an empty entry to identify end of a trace
pub const BPF_STACK_BUILD_ID_EMPTY: i32 = 0;
/// with valid build_id and offset
pub const BPF_STACK_BUILD_ID_VALID: i32 = 1;
/// couldn't get build_id, fallback to ip
pub const BPF_STACK_BUILD_ID_IP: i32 = 2;

pub const BPF_BUILD_ID_SIZE: usize = 20;

#[repr(C)]
pub struct bpf_stack_build_id_t {
    pub status: i32,
    pub build_id: [u8; BPF_BUILD_ID_SIZE],

    /// Alias is `offset`
    pub ip: u64,
}

/// anonymous struct used by BPF_MAP_CREATE command
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_map_create_t {
    /// one of enum bpf_map_type
    pub map_type: u32,
    /// size of key in bytes
    pub key_size: u32,
    /// size of value in bytes
    pub value_size: u32,
    /// max number of entries in a map
    pub max_entries: u32,
    /// BPF_MAP_CREATE related flags defined above.
    pub map_flags: u32,
    /// fd pointing to the inner map
    pub inner_map_fd: u32,
    /// numa node (effective only if BPF_F_NUMA_NODE is set).
    pub numa_node: u32,
    pub map_name: [u8; BPF_OBJ_NAME_LEN],
    /// ifindex of netdev to create on
    pub map_ifindex: u32,
    /// fd pointing to a BTF type data
    pub btf_fd: u32,
    /// BTF type_id of the key
    pub btf_key_type_id: u32,
    /// BTF type_id of the value
    pub btf_value_type_id: u32,
}

/// anonymous struct used by BPF_MAP_*_ELEM commands
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_element_t {
    pub map_fd: u32,
    pub key: u64,

    /// Alias of value
    pub next_key: u64,
    pub flags: u64,
}

/// anonymous struct used by BPF_PROG_LOAD command
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_prog_load_t {
    /// one of enum bpf_prog_type
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    /// verbosity level of verifier
    pub log_level: u32,
    /// size of user buffer
    pub log_size: u32,
    /// user supplied buffer
    pub log_buf: u64,
    /// not used
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; BPF_OBJ_NAME_LEN],
    /// ifindex of netdev to prep for
    pub prog_ifindex: u32,
    /// For some prog types expected attach type must be known at
    /// load time to verify attach type specific parts of prog
    /// (context accesses, allowed helpers, etc).
    pub expected_attach_type: u32,
    /// fd pointing to BTF type data
    pub prog_btf_fd: u32,
    /// userspace bpf_func_info size
    pub func_info_rec_size: u32,
    /// func info
    pub func_info: u64,
    /// number of bpf_func_info records
    pub func_info_cnt: u32,
    /// userspace bpf_line_info size
    pub line_info_rec_size: u32,
    /// line info
    pub line_info: u64,
    /// number of bpf_line_info records
    pub line_info_cnt: u32,
}

/// anonymous struct used by BPF_OBJ_* commands
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_obj_t {
    pub pathname: u64,
    pub bpf_fd: u32,
    pub file_flags: u32,
}

/// anonymous struct used by BPF_PROG_ATTACH/DETACH commands
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_prog_attach_t {
    /// container object to attach to
    pub target_fd: u32,
    /// eBPF program to attach
    pub attach_bpf_fd: u32,
    pub attach_type: u32,
    pub attach_flags: u32,
}

/// anonymous struct used by BPF_PROG_TEST_RUN command
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_prog_test_t {
    pub prog_fd: u32,
    pub retval: u32,
    /// input: len of data_in
    pub data_size_in: u32,
    /// input/output: len of data_out returns ENOSPC if data_out is too small.
    pub data_size_out: u32,
    pub data_in: u64,
    pub data_out: u64,
    pub repeat: u32,
    pub duration: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union bpf_attr_getid_id_t {
    pub start_id: u32,
    pub prog_id: u32,
    pub map_id: u32,
    pub btf_id: u32,
}

/// anonymous struct used by BPF_*_GET_*_ID
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_getid_t {
    pub id: bpf_attr_getid_id_t,
    pub next_id: u32,
    pub open_flags: u32,
}

/// anonymous struct used by BPF_OBJ_GET_INFO_BY_FD
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_info_t {
    pub bpf_fd: u32,
    pub info_len: u32,
    pub info: u64,
}

/// anonymous struct used by BPF_PROG_QUERY command
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_query_t {
    /// container object to query
    pub target_fd: u32,
    pub attach_type: u32,
    pub query_flags: u32,
    pub attach_flags: u32,
    pub prog_ids: u64,
    pub prog_cnt: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_raw_tracepoint_t {
    pub name: u64,
    pub prog_fd: u32,
}

/// anonymous struct for BPF_BTF_LOAD
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_btf_load_t {
    pub btf: u64,
    pub btf_log_buf: u64,
    pub btf_size: u32,
    pub btf_log_size: u32,
    pub btf_log_level: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_attr_task_fd_query_t {
    /// input: pid
    pub pid: u32,
    /// input: fd
    pub fd: u32,
    /// input: flags
    pub flags: u32,
    /// input/output: buf len
    pub buf_len: u32,
    /// input/output:
    ///   tp_name for tracepoint symbol for kprobe filename for uprobe
    pub buf: u64,
    /// output: prod_id
    pub prog_id: u32,
    /// output: BPF_FD_TYPE_*
    pub fd_type: u32,
    /// output: probe_offset
    pub probe_offset: u64,
    /// output: probe_addr
    pub probe_addr: u64,
}

#[repr(C)]
pub union bpf_attr_t {
    pub map_create: bpf_attr_map_create_t,
    pub map_element: bpf_attr_element_t,
    pub prog_load: bpf_attr_prog_load_t,
    pub obj: bpf_attr_obj_t,
    pub prog_attach: bpf_attr_prog_attach_t,
    pub prog_test: bpf_attr_prog_test_t,
    pub getid: bpf_attr_getid_t,
    pub info: bpf_attr_info_t,
    pub query: bpf_attr_query_t,
    pub raw_tracepoint: bpf_attr_raw_tracepoint_t,
    pub btf_load: bpf_attr_btf_load_t,
    pub task_fd_query: bpf_attr_task_fd_query_t,
}

/* The description below is an attempt at providing documentation to eBPF
 * developers about the multiple available eBPF helper functions. It can be
 * parsed and used to produce a manual page. The workflow is the following,
 * and requires the rst2man utility:
 *
 *     $ ./scripts/bpf_helpers_doc.py \
 *             --filename include/uapi/linux/bpf.h > /tmp/bpf-helpers.rst
 *     $ rst2man /tmp/bpf-helpers.rst > /tmp/bpf-helpers.7
 *     $ man /tmp/bpf-helpers.7
 *
 * Note that in order to produce this external documentation, some RST
 * formatting is used in the descriptions to get "bold" and "italics" in
 * manual pages. Also note that the few trailing white spaces are
 * intentional, removing them would break paragraphs for rst2man.
 *
 * Start of BPF helper function descriptions:
 *
 * void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
 * 	Description
 * 		Perform a lookup in *map* for an entry associated to *key*.
 * 	Return
 * 		Map value associated to *key*, or **NULL** if no entry was
 * 		found.
 *
 * int bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)
 * 	Description
 * 		Add or update the value of the entry associated to *key* in
 * 		*map* with *value*. *flags* is one of:
 *
 * 		**BPF_NOEXIST**
 * 			The entry for *key* must not exist in the map.
 * 		**BPF_EXIST**
 * 			The entry for *key* must already exist in the map.
 * 		**BPF_ANY**
 * 			No condition on the existence of the entry for *key*.
 *
 * 		Flag value **BPF_NOEXIST** cannot be used for maps of types
 * 		**BPF_MAP_TYPE_ARRAY** or **BPF_MAP_TYPE_PERCPU_ARRAY**  (all
 * 		elements always exist), the helper would return an error.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_map_delete_elem(struct bpf_map *map, const void *key)
 * 	Description
 * 		Delete entry with *key* from *map*.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_probe_read(void *dst, u32 size, const void *src)
 * 	Description
 * 		For tracing programs, safely attempt to read *size* bytes from
 * 		address *src* and store the data in *dst*.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * u64 bpf_ktime_get_ns(void)
 * 	Description
 * 		Return the time elapsed since system boot, in nanoseconds.
 * 	Return
 * 		Current *ktime*.
 *
 * int bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
 * 	Description
 * 		This helper is a "printk()-like" facility for debugging. It
 * 		prints a message defined by format *fmt* (of size *fmt_size*)
 * 		to file *\/sys/kernel/debug/tracing/trace* from DebugFS, if
 * 		available. It can take up to three additional **u64**
 * 		arguments (as an eBPF helpers, the total number of arguments is
 * 		limited to five).
 *
 * 		Each time the helper is called, it appends a line to the trace.
 * 		The format of the trace is customizable, and the exact output
 * 		one will get depends on the options set in
 * 		*\/sys/kernel/debug/tracing/trace_options* (see also the
 * 		*README* file under the same directory). However, it usually
 * 		defaults to something like:
 *
 * 		::
 *
 * 			telnet-470   [001] .N.. 419421.045894: 0x00000001: <formatted msg>
 *
 * 		In the above:
 *
 * 			* ``telnet`` is the name of the current task.
 * 			* ``470`` is the PID of the current task.
 * 			* ``001`` is the CPU number on which the task is
 * 			  running.
 * 			* In ``.N..``, each character refers to a set of
 * 			  options (whether irqs are enabled, scheduling
 * 			  options, whether hard/softirqs are running, level of
 * 			  preempt_disabled respectively). **N** means that
 * 			  **TIF_NEED_RESCHED** and **PREEMPT_NEED_RESCHED**
 * 			  are set.
 * 			* ``419421.045894`` is a timestamp.
 * 			* ``0x00000001`` is a fake value used by BPF for the
 * 			  instruction pointer register.
 * 			* ``<formatted msg>`` is the message formatted with
 * 			  *fmt*.
 *
 * 		The conversion specifiers supported by *fmt* are similar, but
 * 		more limited than for printk(). They are **%d**, **%i**,
 * 		**%u**, **%x**, **%ld**, **%li**, **%lu**, **%lx**, **%lld**,
 * 		**%lli**, **%llu**, **%llx**, **%p**, **%s**. No modifier (size
 * 		of field, padding with zeroes, etc.) is available, and the
 * 		helper will return **-EINVAL** (but print nothing) if it
 * 		encounters an unknown specifier.
 *
 * 		Also, note that **bpf_trace_printk**\ () is slow, and should
 * 		only be used for debugging purposes. For this reason, a notice
 * 		bloc (spanning several lines) is printed to kernel logs and
 * 		states that the helper should not be used "for production use"
 * 		the first time this helper is used (or more precisely, when
 * 		**trace_printk**\ () buffers are allocated). For passing values
 * 		to user space, perf events should be preferred.
 * 	Return
 * 		The number of bytes written to the buffer, or a negative error
 * 		in case of failure.
 *
 * u32 bpf_get_prandom_u32(void)
 * 	Description
 * 		Get a pseudo-random number.
 *
 * 		From a security point of view, this helper uses its own
 * 		pseudo-random internal state, and cannot be used to infer the
 * 		seed of other random functions in the kernel. However, it is
 * 		essential to note that the generator used by the helper is not
 * 		cryptographically secure.
 * 	Return
 * 		A random 32-bit unsigned value.
 *
 * u32 bpf_get_smp_processor_id(void)
 * 	Description
 * 		Get the SMP (symmetric multiprocessing) processor id. Note that
 * 		all programs run with preemption disabled, which means that the
 * 		SMP processor id is stable during all the execution of the
 * 		program.
 * 	Return
 * 		The SMP id of the processor running the program.
 *
 * int bpf_skb_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len, u64 flags)
 * 	Description
 * 		Store *len* bytes from address *from* into the packet
 * 		associated to *skb*, at *offset*. *flags* are a combination of
 * 		**BPF_F_RECOMPUTE_CSUM** (automatically recompute the
 * 		checksum for the packet after storing the bytes) and
 * 		**BPF_F_INVALIDATE_HASH** (set *skb*\ **->hash**, *skb*\
 * 		**->swhash** and *skb*\ **->l4hash** to 0).
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_l3_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 size)
 * 	Description
 * 		Recompute the layer 3 (e.g. IP) checksum for the packet
 * 		associated to *skb*. Computation is incremental, so the helper
 * 		must know the former value of the header field that was
 * 		modified (*from*), the new value of this field (*to*), and the
 * 		number of bytes (2 or 4) for this field, stored in *size*.
 * 		Alternatively, it is possible to store the difference between
 * 		the previous and the new values of the header field in *to*, by
 * 		setting *from* and *size* to 0. For both methods, *offset*
 * 		indicates the location of the IP checksum within the packet.
 *
 * 		This helper works in combination with **bpf_csum_diff**\ (),
 * 		which does not update the checksum in-place, but offers more
 * 		flexibility and can handle sizes larger than 2 or 4 for the
 * 		checksum to update.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_l4_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags)
 * 	Description
 * 		Recompute the layer 4 (e.g. TCP, UDP or ICMP) checksum for the
 * 		packet associated to *skb*. Computation is incremental, so the
 * 		helper must know the former value of the header field that was
 * 		modified (*from*), the new value of this field (*to*), and the
 * 		number of bytes (2 or 4) for this field, stored on the lowest
 * 		four bits of *flags*. Alternatively, it is possible to store
 * 		the difference between the previous and the new values of the
 * 		header field in *to*, by setting *from* and the four lowest
 * 		bits of *flags* to 0. For both methods, *offset* indicates the
 * 		location of the IP checksum within the packet. In addition to
 * 		the size of the field, *flags* can be added (bitwise OR) actual
 * 		flags. With **BPF_F_MARK_MANGLED_0**, a null checksum is left
 * 		untouched (unless **BPF_F_MARK_ENFORCE** is added as well), and
 * 		for updates resulting in a null checksum the value is set to
 * 		**CSUM_MANGLED_0** instead. Flag **BPF_F_PSEUDO_HDR** indicates
 * 		the checksum is to be computed against a pseudo-header.
 *
 * 		This helper works in combination with **bpf_csum_diff**\ (),
 * 		which does not update the checksum in-place, but offers more
 * 		flexibility and can handle sizes larger than 2 or 4 for the
 * 		checksum to update.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)
 * 	Description
 * 		This special helper is used to trigger a "tail call", or in
 * 		other words, to jump into another eBPF program. The same stack
 * 		frame is used (but values on stack and in registers for the
 * 		caller are not accessible to the callee). This mechanism allows
 * 		for program chaining, either for raising the maximum number of
 * 		available eBPF instructions, or to execute given programs in
 * 		conditional blocks. For security reasons, there is an upper
 * 		limit to the number of successive tail calls that can be
 * 		performed.
 *
 * 		Upon call of this helper, the program attempts to jump into a
 * 		program referenced at index *index* in *prog_array_map*, a
 * 		special map of type **BPF_MAP_TYPE_PROG_ARRAY**, and passes
 * 		*ctx*, a pointer to the context.
 *
 * 		If the call succeeds, the kernel immediately runs the first
 * 		instruction of the new program. This is not a function call,
 * 		and it never returns to the previous program. If the call
 * 		fails, then the helper has no effect, and the caller continues
 * 		to run its subsequent instructions. A call can fail if the
 * 		destination program for the jump does not exist (i.e. *index*
 * 		is superior to the number of entries in *prog_array_map*), or
 * 		if the maximum number of tail calls has been reached for this
 * 		chain of programs. This limit is defined in the kernel by the
 * 		macro **MAX_TAIL_CALL_CNT** (not accessible to user space),
 * 		which is currently set to 32.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_clone_redirect(struct sk_buff *skb, u32 ifindex, u64 flags)
 * 	Description
 * 		Clone and redirect the packet associated to *skb* to another
 * 		net device of index *ifindex*. Both ingress and egress
 * 		interfaces can be used for redirection. The **BPF_F_INGRESS**
 * 		value in *flags* is used to make the distinction (ingress path
 * 		is selected if the flag is present, egress path otherwise).
 * 		This is the only flag supported for now.
 *
 * 		In comparison with **bpf_redirect**\ () helper,
 * 		**bpf_clone_redirect**\ () has the associated cost of
 * 		duplicating the packet buffer, but this can be executed out of
 * 		the eBPF program. Conversely, **bpf_redirect**\ () is more
 * 		efficient, but it is handled through an action code where the
 * 		redirection happens only after the eBPF program has returned.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * u64 bpf_get_current_pid_tgid(void)
 * 	Return
 * 		A 64-bit integer containing the current tgid and pid, and
 * 		created as such:
 * 		*current_task*\ **->tgid << 32 \|**
 * 		*current_task*\ **->pid**.
 *
 * u64 bpf_get_current_uid_gid(void)
 * 	Return
 * 		A 64-bit integer containing the current GID and UID, and
 * 		created as such: *current_gid* **<< 32 \|** *current_uid*.
 *
 * int bpf_get_current_comm(char *buf, u32 size_of_buf)
 * 	Description
 * 		Copy the **comm** attribute of the current task into *buf* of
 * 		*size_of_buf*. The **comm** attribute contains the name of
 * 		the executable (excluding the path) for the current task. The
 * 		*size_of_buf* must be strictly positive. On success, the
 * 		helper makes sure that the *buf* is NUL-terminated. On failure,
 * 		it is filled with zeroes.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * u32 bpf_get_cgroup_classid(struct sk_buff *skb)
 * 	Description
 * 		Retrieve the classid for the current task, i.e. for the net_cls
 * 		cgroup to which *skb* belongs.
 *
 * 		This helper can be used on TC egress path, but not on ingress.
 *
 * 		The net_cls cgroup provides an interface to tag network packets
 * 		based on a user-provided identifier for all traffic coming from
 * 		the tasks belonging to the related cgroup. See also the related
 * 		kernel documentation, available from the Linux sources in file
 * 		*Documentation/cgroup-v1/net_cls.txt*.
 *
 * 		The Linux kernel has two versions for cgroups: there are
 * 		cgroups v1 and cgroups v2. Both are available to users, who can
 * 		use a mixture of them, but note that the net_cls cgroup is for
 * 		cgroup v1 only. This makes it incompatible with BPF programs
 * 		run on cgroups, which is a cgroup-v2-only feature (a socket can
 * 		only hold data for one version of cgroups at a time).
 *
 * 		This helper is only available is the kernel was compiled with
 * 		the **CONFIG_CGROUP_NET_CLASSID** configuration option set to
 * 		"**y**" or to "**m**".
 * 	Return
 * 		The classid, or 0 for the default unconfigured classid.
 *
 * int bpf_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
 * 	Description
 * 		Push a *vlan_tci* (VLAN tag control information) of protocol
 * 		*vlan_proto* to the packet associated to *skb*, then update
 * 		the checksum. Note that if *vlan_proto* is different from
 * 		**ETH_P_8021Q** and **ETH_P_8021AD**, it is considered to
 * 		be **ETH_P_8021Q**.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_vlan_pop(struct sk_buff *skb)
 * 	Description
 * 		Pop a VLAN header from the packet associated to *skb*.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_get_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)
 * 	Description
 * 		Get tunnel metadata. This helper takes a pointer *key* to an
 * 		empty **struct bpf_tunnel_key** of **size**, that will be
 * 		filled with tunnel metadata for the packet associated to *skb*.
 * 		The *flags* can be set to **BPF_F_TUNINFO_IPV6**, which
 * 		indicates that the tunnel is based on IPv6 protocol instead of
 * 		IPv4.
 *
 * 		The **struct bpf_tunnel_key** is an object that generalizes the
 * 		principal parameters used by various tunneling protocols into a
 * 		single struct. This way, it can be used to easily make a
 * 		decision based on the contents of the encapsulation header,
 * 		"summarized" in this struct. In particular, it holds the IP
 * 		address of the remote end (IPv4 or IPv6, depending on the case)
 * 		in *key*\ **->remote_ipv4** or *key*\ **->remote_ipv6**. Also,
 * 		this struct exposes the *key*\ **->tunnel_id**, which is
 * 		generally mapped to a VNI (Virtual Network Identifier), making
 * 		it programmable together with the **bpf_skb_set_tunnel_key**\
 * 		() helper.
 *
 * 		Let's imagine that the following code is part of a program
 * 		attached to the TC ingress interface, on one end of a GRE
 * 		tunnel, and is supposed to filter out all messages coming from
 * 		remote ends with IPv4 address other than 10.0.0.1:
 *
 * 		::
 *
 * 			int ret;
 * 			struct bpf_tunnel_key key = {};
 *
 * 			ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key), 0);
 * 			if (ret < 0)
 * 				return TC_ACT_SHOT;	// drop packet
 *
 * 			if (key.remote_ipv4 != 0x0a000001)
 * 				return TC_ACT_SHOT;	// drop packet
 *
 * 			return TC_ACT_OK;		// accept packet
 *
 * 		This interface can also be used with all encapsulation devices
 * 		that can operate in "collect metadata" mode: instead of having
 * 		one network device per specific configuration, the "collect
 * 		metadata" mode only requires a single device where the
 * 		configuration can be extracted from this helper.
 *
 * 		This can be used together with various tunnels such as VXLan,
 * 		Geneve, GRE or IP in IP (IPIP).
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_set_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)
 * 	Description
 * 		Populate tunnel metadata for packet associated to *skb.* The
 * 		tunnel metadata is set to the contents of *key*, of *size*. The
 * 		*flags* can be set to a combination of the following values:
 *
 * 		**BPF_F_TUNINFO_IPV6**
 * 			Indicate that the tunnel is based on IPv6 protocol
 * 			instead of IPv4.
 * 		**BPF_F_ZERO_CSUM_TX**
 * 			For IPv4 packets, add a flag to tunnel metadata
 * 			indicating that checksum computation should be skipped
 * 			and checksum set to zeroes.
 * 		**BPF_F_DONT_FRAGMENT**
 * 			Add a flag to tunnel metadata indicating that the
 * 			packet should not be fragmented.
 * 		**BPF_F_SEQ_NUMBER**
 * 			Add a flag to tunnel metadata indicating that a
 * 			sequence number should be added to tunnel header before
 * 			sending the packet. This flag was added for GRE
 * 			encapsulation, but might be used with other protocols
 * 			as well in the future.
 *
 * 		Here is a typical usage on the transmit path:
 *
 * 		::
 *
 * 			struct bpf_tunnel_key key;
 * 			     populate key ...
 * 			bpf_skb_set_tunnel_key(skb, &key, sizeof(key), 0);
 * 			bpf_clone_redirect(skb, vxlan_dev_ifindex, 0);
 *
 * 		See also the description of the **bpf_skb_get_tunnel_key**\ ()
 * 		helper for additional information.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * u64 bpf_perf_event_read(struct bpf_map *map, u64 flags)
 * 	Description
 * 		Read the value of a perf event counter. This helper relies on a
 * 		*map* of type **BPF_MAP_TYPE_PERF_EVENT_ARRAY**. The nature of
 * 		the perf event counter is selected when *map* is updated with
 * 		perf event file descriptors. The *map* is an array whose size
 * 		is the number of available CPUs, and each cell contains a value
 * 		relative to one CPU. The value to retrieve is indicated by
 * 		*flags*, that contains the index of the CPU to look up, masked
 * 		with **BPF_F_INDEX_MASK**. Alternatively, *flags* can be set to
 * 		**BPF_F_CURRENT_CPU** to indicate that the value for the
 * 		current CPU should be retrieved.
 *
 * 		Note that before Linux 4.13, only hardware perf event can be
 * 		retrieved.
 *
 * 		Also, be aware that the newer helper
 * 		**bpf_perf_event_read_value**\ () is recommended over
 * 		**bpf_perf_event_read**\ () in general. The latter has some ABI
 * 		quirks where error and counter value are used as a return code
 * 		(which is wrong to do since ranges may overlap). This issue is
 * 		fixed with **bpf_perf_event_read_value**\ (), which at the same
 * 		time provides more features over the **bpf_perf_event_read**\
 * 		() interface. Please refer to the description of
 * 		**bpf_perf_event_read_value**\ () for details.
 * 	Return
 * 		The value of the perf event counter read from the map, or a
 * 		negative error code in case of failure.
 *
 * int bpf_redirect(u32 ifindex, u64 flags)
 * 	Description
 * 		Redirect the packet to another net device of index *ifindex*.
 * 		This helper is somewhat similar to **bpf_clone_redirect**\
 * 		(), except that the packet is not cloned, which provides
 * 		increased performance.
 *
 * 		Except for XDP, both ingress and egress interfaces can be used
 * 		for redirection. The **BPF_F_INGRESS** value in *flags* is used
 * 		to make the distinction (ingress path is selected if the flag
 * 		is present, egress path otherwise). Currently, XDP only
 * 		supports redirection to the egress interface, and accepts no
 * 		flag at all.
 *
 * 		The same effect can be attained with the more generic
 * 		**bpf_redirect_map**\ (), which requires specific maps to be
 * 		used but offers better performance.
 * 	Return
 * 		For XDP, the helper returns **XDP_REDIRECT** on success or
 * 		**XDP_ABORTED** on error. For other program types, the values
 * 		are **TC_ACT_REDIRECT** on success or **TC_ACT_SHOT** on
 * 		error.
 *
 * u32 bpf_get_route_realm(struct sk_buff *skb)
 * 	Description
 * 		Retrieve the realm or the route, that is to say the
 * 		**tclassid** field of the destination for the *skb*. The
 * 		indentifier retrieved is a user-provided tag, similar to the
 * 		one used with the net_cls cgroup (see description for
 * 		**bpf_get_cgroup_classid**\ () helper), but here this tag is
 * 		held by a route (a destination entry), not by a task.
 *
 * 		Retrieving this identifier works with the clsact TC egress hook
 * 		(see also **tc-bpf(8)**), or alternatively on conventional
 * 		classful egress qdiscs, but not on TC ingress path. In case of
 * 		clsact TC egress hook, this has the advantage that, internally,
 * 		the destination entry has not been dropped yet in the transmit
 * 		path. Therefore, the destination entry does not need to be
 * 		artificially held via **netif_keep_dst**\ () for a classful
 * 		qdisc until the *skb* is freed.
 *
 * 		This helper is available only if the kernel was compiled with
 * 		**CONFIG_IP_ROUTE_CLASSID** configuration option.
 * 	Return
 * 		The realm of the route for the packet associated to *skb*, or 0
 * 		if none was found.
 *
 * int bpf_perf_event_output(struct pt_reg *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)
 * 	Description
 * 		Write raw *data* blob into a special BPF perf event held by
 * 		*map* of type **BPF_MAP_TYPE_PERF_EVENT_ARRAY**. This perf
 * 		event must have the following attributes: **PERF_SAMPLE_RAW**
 * 		as **sample_type**, **PERF_TYPE_SOFTWARE** as **type**, and
 * 		**PERF_COUNT_SW_BPF_OUTPUT** as **config**.
 *
 * 		The *flags* are used to indicate the index in *map* for which
 * 		the value must be put, masked with **BPF_F_INDEX_MASK**.
 * 		Alternatively, *flags* can be set to **BPF_F_CURRENT_CPU**
 * 		to indicate that the index of the current CPU core should be
 * 		used.
 *
 * 		The value to write, of *size*, is passed through eBPF stack and
 * 		pointed by *data*.
 *
 * 		The context of the program *ctx* needs also be passed to the
 * 		helper.
 *
 * 		On user space, a program willing to read the values needs to
 * 		call **perf_event_open**\ () on the perf event (either for
 * 		one or for all CPUs) and to store the file descriptor into the
 * 		*map*. This must be done before the eBPF program can send data
 * 		into it. An example is available in file
 * 		*samples/bpf/trace_output_user.c* in the Linux kernel source
 * 		tree (the eBPF program counterpart is in
 * 		*samples/bpf/trace_output_kern.c*).
 *
 * 		**bpf_perf_event_output**\ () achieves better performance
 * 		than **bpf_trace_printk**\ () for sharing data with user
 * 		space, and is much better suitable for streaming data from eBPF
 * 		programs.
 *
 * 		Note that this helper is not restricted to tracing use cases
 * 		and can be used with programs attached to TC or XDP as well,
 * 		where it allows for passing data to user space listeners. Data
 * 		can be:
 *
 * 		* Only custom structs,
 * 		* Only the packet payload, or
 * 		* A combination of both.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_load_bytes(const struct sk_buff *skb, u32 offset, void *to, u32 len)
 * 	Description
 * 		This helper was provided as an easy way to load data from a
 * 		packet. It can be used to load *len* bytes from *offset* from
 * 		the packet associated to *skb*, into the buffer pointed by
 * 		*to*.
 *
 * 		Since Linux 4.7, usage of this helper has mostly been replaced
 * 		by "direct packet access", enabling packet data to be
 * 		manipulated with *skb*\ **->data** and *skb*\ **->data_end**
 * 		pointing respectively to the first byte of packet data and to
 * 		the byte after the last byte of packet data. However, it
 * 		remains useful if one wishes to read large quantities of data
 * 		at once from a packet into the eBPF stack.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_get_stackid(struct pt_reg *ctx, struct bpf_map *map, u64 flags)
 * 	Description
 * 		Walk a user or a kernel stack and return its id. To achieve
 * 		this, the helper needs *ctx*, which is a pointer to the context
 * 		on which the tracing program is executed, and a pointer to a
 * 		*map* of type **BPF_MAP_TYPE_STACK_TRACE**.
 *
 * 		The last argument, *flags*, holds the number of stack frames to
 * 		skip (from 0 to 255), masked with
 * 		**BPF_F_SKIP_FIELD_MASK**. The next bits can be used to set
 * 		a combination of the following flags:
 *
 * 		**BPF_F_USER_STACK**
 * 			Collect a user space stack instead of a kernel stack.
 * 		**BPF_F_FAST_STACK_CMP**
 * 			Compare stacks by hash only.
 * 		**BPF_F_REUSE_STACKID**
 * 			If two different stacks hash into the same *stackid*,
 * 			discard the old one.
 *
 * 		The stack id retrieved is a 32 bit long integer handle which
 * 		can be further combined with other data (including other stack
 * 		ids) and used as a key into maps. This can be useful for
 * 		generating a variety of graphs (such as flame graphs or off-cpu
 * 		graphs).
 *
 * 		For walking a stack, this helper is an improvement over
 * 		**bpf_probe_read**\ (), which can be used with unrolled loops
 * 		but is not efficient and consumes a lot of eBPF instructions.
 * 		Instead, **bpf_get_stackid**\ () can collect up to
 * 		**PERF_MAX_STACK_DEPTH** both kernel and user frames. Note that
 * 		this limit can be controlled with the **sysctl** program, and
 * 		that it should be manually increased in order to profile long
 * 		user stacks (such as stacks for Java programs). To do so, use:
 *
 * 		::
 *
 * 			# sysctl kernel.perf_event_max_stack=<new value>
 * 	Return
 * 		The positive or null stack id on success, or a negative error
 * 		in case of failure.
 *
 * s64 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)
 * 	Description
 * 		Compute a checksum difference, from the raw buffer pointed by
 * 		*from*, of length *from_size* (that must be a multiple of 4),
 * 		towards the raw buffer pointed by *to*, of size *to_size*
 * 		(same remark). An optional *seed* can be added to the value
 * 		(this can be cascaded, the seed may come from a previous call
 * 		to the helper).
 *
 * 		This is flexible enough to be used in several ways:
 *
 * 		* With *from_size* == 0, *to_size* > 0 and *seed* set to
 * 		  checksum, it can be used when pushing new data.
 * 		* With *from_size* > 0, *to_size* == 0 and *seed* set to
 * 		  checksum, it can be used when removing data from a packet.
 * 		* With *from_size* > 0, *to_size* > 0 and *seed* set to 0, it
 * 		  can be used to compute a diff. Note that *from_size* and
 * 		  *to_size* do not need to be equal.
 *
 * 		This helper can be used in combination with
 * 		**bpf_l3_csum_replace**\ () and **bpf_l4_csum_replace**\ (), to
 * 		which one can feed in the difference computed with
 * 		**bpf_csum_diff**\ ().
 * 	Return
 * 		The checksum result, or a negative error code in case of
 * 		failure.
 *
 * int bpf_skb_get_tunnel_opt(struct sk_buff *skb, u8 *opt, u32 size)
 * 	Description
 * 		Retrieve tunnel options metadata for the packet associated to
 * 		*skb*, and store the raw tunnel option data to the buffer *opt*
 * 		of *size*.
 *
 * 		This helper can be used with encapsulation devices that can
 * 		operate in "collect metadata" mode (please refer to the related
 * 		note in the description of **bpf_skb_get_tunnel_key**\ () for
 * 		more details). A particular example where this can be used is
 * 		in combination with the Geneve encapsulation protocol, where it
 * 		allows for pushing (with **bpf_skb_get_tunnel_opt**\ () helper)
 * 		and retrieving arbitrary TLVs (Type-Length-Value headers) from
 * 		the eBPF program. This allows for full customization of these
 * 		headers.
 * 	Return
 * 		The size of the option data retrieved.
 *
 * int bpf_skb_set_tunnel_opt(struct sk_buff *skb, u8 *opt, u32 size)
 * 	Description
 * 		Set tunnel options metadata for the packet associated to *skb*
 * 		to the option data contained in the raw buffer *opt* of *size*.
 *
 * 		See also the description of the **bpf_skb_get_tunnel_opt**\ ()
 * 		helper for additional information.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_change_proto(struct sk_buff *skb, __be16 proto, u64 flags)
 * 	Description
 * 		Change the protocol of the *skb* to *proto*. Currently
 * 		supported are transition from IPv4 to IPv6, and from IPv6 to
 * 		IPv4. The helper takes care of the groundwork for the
 * 		transition, including resizing the socket buffer. The eBPF
 * 		program is expected to fill the new headers, if any, via
 * 		**skb_store_bytes**\ () and to recompute the checksums with
 * 		**bpf_l3_csum_replace**\ () and **bpf_l4_csum_replace**\
 * 		(). The main case for this helper is to perform NAT64
 * 		operations out of an eBPF program.
 *
 * 		Internally, the GSO type is marked as dodgy so that headers are
 * 		checked and segments are recalculated by the GSO/GRO engine.
 * 		The size for GSO target is adapted as well.
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_change_type(struct sk_buff *skb, u32 type)
 * 	Description
 * 		Change the packet type for the packet associated to *skb*. This
 * 		comes down to setting *skb*\ **->pkt_type** to *type*, except
 * 		the eBPF program does not have a write access to *skb*\
 * 		**->pkt_type** beside this helper. Using a helper here allows
 * 		for graceful handling of errors.
 *
 * 		The major use case is to change incoming *skb*s to
 * 		**PACKET_HOST** in a programmatic way instead of having to
 * 		recirculate via **redirect**\ (..., **BPF_F_INGRESS**), for
 * 		example.
 *
 * 		Note that *type* only allows certain values. At this time, they
 * 		are:
 *
 * 		**PACKET_HOST**
 * 			Packet is for us.
 * 		**PACKET_BROADCAST**
 * 			Send packet to all.
 * 		**PACKET_MULTICAST**
 * 			Send packet to group.
 * 		**PACKET_OTHERHOST**
 * 			Send packet to someone else.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_under_cgroup(struct sk_buff *skb, struct bpf_map *map, u32 index)
 * 	Description
 * 		Check whether *skb* is a descendant of the cgroup2 held by
 * 		*map* of type **BPF_MAP_TYPE_CGROUP_ARRAY**, at *index*.
 * 	Return
 * 		The return value depends on the result of the test, and can be:
 *
 * 		* 0, if the *skb* failed the cgroup2 descendant test.
 * 		* 1, if the *skb* succeeded the cgroup2 descendant test.
 * 		* A negative error code, if an error occurred.
 *
 * u32 bpf_get_hash_recalc(struct sk_buff *skb)
 * 	Description
 * 		Retrieve the hash of the packet, *skb*\ **->hash**. If it is
 * 		not set, in particular if the hash was cleared due to mangling,
 * 		recompute this hash. Later accesses to the hash can be done
 * 		directly with *skb*\ **->hash**.
 *
 * 		Calling **bpf_set_hash_invalid**\ (), changing a packet
 * 		prototype with **bpf_skb_change_proto**\ (), or calling
 * 		**bpf_skb_store_bytes**\ () with the
 * 		**BPF_F_INVALIDATE_HASH** are actions susceptible to clear
 * 		the hash and to trigger a new computation for the next call to
 * 		**bpf_get_hash_recalc**\ ().
 * 	Return
 * 		The 32-bit hash.
 *
 * u64 bpf_get_current_task(void)
 * 	Return
 * 		A pointer to the current task struct.
 *
 * int bpf_probe_write_user(void *dst, const void *src, u32 len)
 * 	Description
 * 		Attempt in a safe way to write *len* bytes from the buffer
 * 		*src* to *dst* in memory. It only works for threads that are in
 * 		user context, and *dst* must be a valid user space address.
 *
 * 		This helper should not be used to implement any kind of
 * 		security mechanism because of TOC-TOU attacks, but rather to
 * 		debug, divert, and manipulate execution of semi-cooperative
 * 		processes.
 *
 * 		Keep in mind that this feature is meant for experiments, and it
 * 		has a risk of crashing the system and running programs.
 * 		Therefore, when an eBPF program using this helper is attached,
 * 		a warning including PID and process name is printed to kernel
 * 		logs.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_current_task_under_cgroup(struct bpf_map *map, u32 index)
 * 	Description
 * 		Check whether the probe is being run is the context of a given
 * 		subset of the cgroup2 hierarchy. The cgroup2 to test is held by
 * 		*map* of type **BPF_MAP_TYPE_CGROUP_ARRAY**, at *index*.
 * 	Return
 * 		The return value depends on the result of the test, and can be:
 *
 * 		* 0, if the *skb* task belongs to the cgroup2.
 * 		* 1, if the *skb* task does not belong to the cgroup2.
 * 		* A negative error code, if an error occurred.
 *
 * int bpf_skb_change_tail(struct sk_buff *skb, u32 len, u64 flags)
 * 	Description
 * 		Resize (trim or grow) the packet associated to *skb* to the
 * 		new *len*. The *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		The basic idea is that the helper performs the needed work to
 * 		change the size of the packet, then the eBPF program rewrites
 * 		the rest via helpers like **bpf_skb_store_bytes**\ (),
 * 		**bpf_l3_csum_replace**\ (), **bpf_l3_csum_replace**\ ()
 * 		and others. This helper is a slow path utility intended for
 * 		replies with control messages. And because it is targeted for
 * 		slow path, the helper itself can afford to be slow: it
 * 		implicitly linearizes, unclones and drops offloads from the
 * 		*skb*.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_pull_data(struct sk_buff *skb, u32 len)
 * 	Description
 * 		Pull in non-linear data in case the *skb* is non-linear and not
 * 		all of *len* are part of the linear section. Make *len* bytes
 * 		from *skb* readable and writable. If a zero value is passed for
 * 		*len*, then the whole length of the *skb* is pulled.
 *
 * 		This helper is only needed for reading and writing with direct
 * 		packet access.
 *
 * 		For direct packet access, testing that offsets to access
 * 		are within packet boundaries (test on *skb*\ **->data_end**) is
 * 		susceptible to fail if offsets are invalid, or if the requested
 * 		data is in non-linear parts of the *skb*. On failure the
 * 		program can just bail out, or in the case of a non-linear
 * 		buffer, use a helper to make the data available. The
 * 		**bpf_skb_load_bytes**\ () helper is a first solution to access
 * 		the data. Another one consists in using **bpf_skb_pull_data**
 * 		to pull in once the non-linear parts, then retesting and
 * 		eventually access the data.
 *
 * 		At the same time, this also makes sure the *skb* is uncloned,
 * 		which is a necessary condition for direct write. As this needs
 * 		to be an invariant for the write part only, the verifier
 * 		detects writes and adds a prologue that is calling
 * 		**bpf_skb_pull_data()** to effectively unclone the *skb* from
 * 		the very beginning in case it is indeed cloned.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * s64 bpf_csum_update(struct sk_buff *skb, __wsum csum)
 * 	Description
 * 		Add the checksum *csum* into *skb*\ **->csum** in case the
 * 		driver has supplied a checksum for the entire packet into that
 * 		field. Return an error otherwise. This helper is intended to be
 * 		used in combination with **bpf_csum_diff**\ (), in particular
 * 		when the checksum needs to be updated after data has been
 * 		written into the packet through direct packet access.
 * 	Return
 * 		The checksum on success, or a negative error code in case of
 * 		failure.
 *
 * void bpf_set_hash_invalid(struct sk_buff *skb)
 * 	Description
 * 		Invalidate the current *skb*\ **->hash**. It can be used after
 * 		mangling on headers through direct packet access, in order to
 * 		indicate that the hash is outdated and to trigger a
 * 		recalculation the next time the kernel tries to access this
 * 		hash or when the **bpf_get_hash_recalc**\ () helper is called.
 *
 * int bpf_get_numa_node_id(void)
 * 	Description
 * 		Return the id of the current NUMA node. The primary use case
 * 		for this helper is the selection of sockets for the local NUMA
 * 		node, when the program is attached to sockets using the
 * 		**SO_ATTACH_REUSEPORT_EBPF** option (see also **socket(7)**),
 * 		but the helper is also available to other eBPF program types,
 * 		similarly to **bpf_get_smp_processor_id**\ ().
 * 	Return
 * 		The id of current NUMA node.
 *
 * int bpf_skb_change_head(struct sk_buff *skb, u32 len, u64 flags)
 * 	Description
 * 		Grows headroom of packet associated to *skb* and adjusts the
 * 		offset of the MAC header accordingly, adding *len* bytes of
 * 		space. It automatically extends and reallocates memory as
 * 		required.
 *
 * 		This helper can be used on a layer 3 *skb* to push a MAC header
 * 		for redirection into a layer 2 device.
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_xdp_adjust_head(struct xdp_buff *xdp_md, int delta)
 * 	Description
 * 		Adjust (move) *xdp_md*\ **->data** by *delta* bytes. Note that
 * 		it is possible to use a negative value for *delta*. This helper
 * 		can be used to prepare the packet for pushing or popping
 * 		headers.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
 * 	Description
 * 		Copy a NUL terminated string from an unsafe address
 * 		*unsafe_ptr* to *dst*. The *size* should include the
 * 		terminating NUL byte. In case the string length is smaller than
 * 		*size*, the target is not padded with further NUL bytes. If the
 * 		string length is larger than *size*, just *size*-1 bytes are
 * 		copied and the last byte is set to NUL.
 *
 * 		On success, the length of the copied string is returned. This
 * 		makes this helper useful in tracing programs for reading
 * 		strings, and more importantly to get its length at runtime. See
 * 		the following snippet:
 *
 * 		::
 *
 * 			SEC("kprobe/sys_open")
 * 			void bpf_sys_open(struct pt_regs *ctx)
 * 			{
 * 			        char buf[PATHLEN]; // PATHLEN is defined to 256
 * 			        int res = bpf_probe_read_str(buf, sizeof(buf),
 * 				                             ctx->di);
 *
 * 				// Consume buf, for example push it to
 * 				// userspace via bpf_perf_event_output(); we
 * 				// can use res (the string length) as event
 * 				// size, after checking its boundaries.
 * 			}
 *
 * 		In comparison, using **bpf_probe_read()** helper here instead
 * 		to read the string would require to estimate the length at
 * 		compile time, and would often result in copying more memory
 * 		than necessary.
 *
 * 		Another useful use case is when parsing individual process
 * 		arguments or individual environment variables navigating
 * 		*current*\ **->mm->arg_start** and *current*\
 * 		**->mm->env_start**: using this helper and the return value,
 * 		one can quickly iterate at the right offset of the memory area.
 * 	Return
 * 		On success, the strictly positive length of the string,
 * 		including the trailing NUL character. On error, a negative
 * 		value.
 *
 * u64 bpf_get_socket_cookie(struct sk_buff *skb)
 * 	Description
 * 		If the **struct sk_buff** pointed by *skb* has a known socket,
 * 		retrieve the cookie (generated by the kernel) of this socket.
 * 		If no cookie has been set yet, generate a new cookie. Once
 * 		generated, the socket cookie remains stable for the life of the
 * 		socket. This helper can be useful for monitoring per socket
 * 		networking traffic statistics as it provides a unique socket
 * 		identifier per namespace.
 * 	Return
 * 		A 8-byte long non-decreasing number on success, or 0 if the
 * 		socket field is missing inside *skb*.
 *
 * u64 bpf_get_socket_cookie(struct bpf_sock_addr *ctx)
 * 	Description
 * 		Equivalent to bpf_get_socket_cookie() helper that accepts
 * 		*skb*, but gets socket from **struct bpf_sock_addr** context.
 * 	Return
 * 		A 8-byte long non-decreasing number.
 *
 * u64 bpf_get_socket_cookie(struct bpf_sock_ops *ctx)
 * 	Description
 * 		Equivalent to bpf_get_socket_cookie() helper that accepts
 * 		*skb*, but gets socket from **struct bpf_sock_ops** context.
 * 	Return
 * 		A 8-byte long non-decreasing number.
 *
 * u32 bpf_get_socket_uid(struct sk_buff *skb)
 * 	Return
 * 		The owner UID of the socket associated to *skb*. If the socket
 * 		is **NULL**, or if it is not a full socket (i.e. if it is a
 * 		time-wait or a request socket instead), **overflowuid** value
 * 		is returned (note that **overflowuid** might also be the actual
 * 		UID value for the socket).
 *
 * u32 bpf_set_hash(struct sk_buff *skb, u32 hash)
 * 	Description
 * 		Set the full hash for *skb* (set the field *skb*\ **->hash**)
 * 		to value *hash*.
 * 	Return
 * 		0
 *
 * int bpf_setsockopt(struct bpf_sock_ops *bpf_socket, int level, int optname, char *optval, int optlen)
 * 	Description
 * 		Emulate a call to **setsockopt()** on the socket associated to
 * 		*bpf_socket*, which must be a full socket. The *level* at
 * 		which the option resides and the name *optname* of the option
 * 		must be specified, see **setsockopt(2)** for more information.
 * 		The option value of length *optlen* is pointed by *optval*.
 *
 * 		This helper actually implements a subset of **setsockopt()**.
 * 		It supports the following *level*\ s:
 *
 * 		* **SOL_SOCKET**, which supports the following *optname*\ s:
 * 		  **SO_RCVBUF**, **SO_SNDBUF**, **SO_MAX_PACING_RATE**,
 * 		  **SO_PRIORITY**, **SO_RCVLOWAT**, **SO_MARK**.
 * 		* **IPPROTO_TCP**, which supports the following *optname*\ s:
 * 		  **TCP_CONGESTION**, **TCP_BPF_IW**,
 * 		  **TCP_BPF_SNDCWND_CLAMP**.
 * 		* **IPPROTO_IP**, which supports *optname* **IP_TOS**.
 * 		* **IPPROTO_IPV6**, which supports *optname* **IPV6_TCLASS**.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_adjust_room(struct sk_buff *skb, s32 len_diff, u32 mode, u64 flags)
 * 	Description
 * 		Grow or shrink the room for data in the packet associated to
 * 		*skb* by *len_diff*, and according to the selected *mode*.
 *
 * 		There is a single supported mode at this time:
 *
 * 		* **BPF_ADJ_ROOM_NET**: Adjust room at the network layer
 * 		  (room space is added or removed below the layer 3 header).
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)
 * 	Description
 * 		Redirect the packet to the endpoint referenced by *map* at
 * 		index *key*. Depending on its type, this *map* can contain
 * 		references to net devices (for forwarding packets through other
 * 		ports), or to CPUs (for redirecting XDP frames to another CPU;
 * 		but this is only implemented for native XDP (with driver
 * 		support) as of this writing).
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		When used to redirect packets to net devices, this helper
 * 		provides a high performance increase over **bpf_redirect**\ ().
 * 		This is due to various implementation details of the underlying
 * 		mechanisms, one of which is the fact that **bpf_redirect_map**\
 * 		() tries to send packet as a "bulk" to the device.
 * 	Return
 * 		**XDP_REDIRECT** on success, or **XDP_ABORTED** on error.
 *
 * int bpf_sk_redirect_map(struct bpf_map *map, u32 key, u64 flags)
 * 	Description
 * 		Redirect the packet to the socket referenced by *map* (of type
 * 		**BPF_MAP_TYPE_SOCKMAP**) at index *key*. Both ingress and
 * 		egress interfaces can be used for redirection. The
 * 		**BPF_F_INGRESS** value in *flags* is used to make the
 * 		distinction (ingress path is selected if the flag is present,
 * 		egress path otherwise). This is the only flag supported for now.
 * 	Return
 * 		**SK_PASS** on success, or **SK_DROP** on error.
 *
 * int bpf_sock_map_update(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags)
 * 	Description
 * 		Add an entry to, or update a *map* referencing sockets. The
 * 		*skops* is used as a new value for the entry associated to
 * 		*key*. *flags* is one of:
 *
 * 		**BPF_NOEXIST**
 * 			The entry for *key* must not exist in the map.
 * 		**BPF_EXIST**
 * 			The entry for *key* must already exist in the map.
 * 		**BPF_ANY**
 * 			No condition on the existence of the entry for *key*.
 *
 * 		If the *map* has eBPF programs (parser and verdict), those will
 * 		be inherited by the socket being added. If the socket is
 * 		already attached to eBPF programs, this results in an error.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_xdp_adjust_meta(struct xdp_buff *xdp_md, int delta)
 * 	Description
 * 		Adjust the address pointed by *xdp_md*\ **->data_meta** by
 * 		*delta* (which can be positive or negative). Note that this
 * 		operation modifies the address stored in *xdp_md*\ **->data**,
 * 		so the latter must be loaded only after the helper has been
 * 		called.
 *
 * 		The use of *xdp_md*\ **->data_meta** is optional and programs
 * 		are not required to use it. The rationale is that when the
 * 		packet is processed with XDP (e.g. as DoS filter), it is
 * 		possible to push further meta data along with it before passing
 * 		to the stack, and to give the guarantee that an ingress eBPF
 * 		program attached as a TC classifier on the same device can pick
 * 		this up for further post-processing. Since TC works with socket
 * 		buffers, it remains possible to set from XDP the **mark** or
 * 		**priority** pointers, or other pointers for the socket buffer.
 * 		Having this scratch space generic and programmable allows for
 * 		more flexibility as the user is free to store whatever meta
 * 		data they need.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_perf_event_read_value(struct bpf_map *map, u64 flags, struct bpf_perf_event_value *buf, u32 buf_size)
 * 	Description
 * 		Read the value of a perf event counter, and store it into *buf*
 * 		of size *buf_size*. This helper relies on a *map* of type
 * 		**BPF_MAP_TYPE_PERF_EVENT_ARRAY**. The nature of the perf event
 * 		counter is selected when *map* is updated with perf event file
 * 		descriptors. The *map* is an array whose size is the number of
 * 		available CPUs, and each cell contains a value relative to one
 * 		CPU. The value to retrieve is indicated by *flags*, that
 * 		contains the index of the CPU to look up, masked with
 * 		**BPF_F_INDEX_MASK**. Alternatively, *flags* can be set to
 * 		**BPF_F_CURRENT_CPU** to indicate that the value for the
 * 		current CPU should be retrieved.
 *
 * 		This helper behaves in a way close to
 * 		**bpf_perf_event_read**\ () helper, save that instead of
 * 		just returning the value observed, it fills the *buf*
 * 		structure. This allows for additional data to be retrieved: in
 * 		particular, the enabled and running times (in *buf*\
 * 		**->enabled** and *buf*\ **->running**, respectively) are
 * 		copied. In general, **bpf_perf_event_read_value**\ () is
 * 		recommended over **bpf_perf_event_read**\ (), which has some
 * 		ABI issues and provides fewer functionalities.
 *
 * 		These values are interesting, because hardware PMU (Performance
 * 		Monitoring Unit) counters are limited resources. When there are
 * 		more PMU based perf events opened than available counters,
 * 		kernel will multiplex these events so each event gets certain
 * 		percentage (but not all) of the PMU time. In case that
 * 		multiplexing happens, the number of samples or counter value
 * 		will not reflect the case compared to when no multiplexing
 * 		occurs. This makes comparison between different runs difficult.
 * 		Typically, the counter value should be normalized before
 * 		comparing to other experiments. The usual normalization is done
 * 		as follows.
 *
 * 		::
 *
 * 			normalized_counter = counter * t_enabled / t_running
 *
 * 		Where t_enabled is the time enabled for event and t_running is
 * 		the time running for event since last normalization. The
 * 		enabled and running times are accumulated since the perf event
 * 		open. To achieve scaling factor between two invocations of an
 * 		eBPF program, users can can use CPU id as the key (which is
 * 		typical for perf array usage model) to remember the previous
 * 		value and do the calculation inside the eBPF program.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, u32 buf_size)
 * 	Description
 * 		For en eBPF program attached to a perf event, retrieve the
 * 		value of the event counter associated to *ctx* and store it in
 * 		the structure pointed by *buf* and of size *buf_size*. Enabled
 * 		and running times are also stored in the structure (see
 * 		description of helper **bpf_perf_event_read_value**\ () for
 * 		more details).
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_getsockopt(struct bpf_sock_ops *bpf_socket, int level, int optname, char *optval, int optlen)
 * 	Description
 * 		Emulate a call to **getsockopt()** on the socket associated to
 * 		*bpf_socket*, which must be a full socket. The *level* at
 * 		which the option resides and the name *optname* of the option
 * 		must be specified, see **getsockopt(2)** for more information.
 * 		The retrieved value is stored in the structure pointed by
 * 		*opval* and of length *optlen*.
 *
 * 		This helper actually implements a subset of **getsockopt()**.
 * 		It supports the following *level*\ s:
 *
 * 		* **IPPROTO_TCP**, which supports *optname*
 * 		  **TCP_CONGESTION**.
 * 		* **IPPROTO_IP**, which supports *optname* **IP_TOS**.
 * 		* **IPPROTO_IPV6**, which supports *optname* **IPV6_TCLASS**.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_override_return(struct pt_reg *regs, u64 rc)
 * 	Description
 * 		Used for error injection, this helper uses kprobes to override
 * 		the return value of the probed function, and to set it to *rc*.
 * 		The first argument is the context *regs* on which the kprobe
 * 		works.
 *
 * 		This helper works by setting setting the PC (program counter)
 * 		to an override function which is run in place of the original
 * 		probed function. This means the probed function is not run at
 * 		all. The replacement function just returns with the required
 * 		value.
 *
 * 		This helper has security implications, and thus is subject to
 * 		restrictions. It is only available if the kernel was compiled
 * 		with the **CONFIG_BPF_KPROBE_OVERRIDE** configuration
 * 		option, and in this case it only works on functions tagged with
 * 		**ALLOW_ERROR_INJECTION** in the kernel code.
 *
 * 		Also, the helper is only available for the architectures having
 * 		the CONFIG_FUNCTION_ERROR_INJECTION option. As of this writing,
 * 		x86 architecture is the only one to support this feature.
 * 	Return
 * 		0
 *
 * int bpf_sock_ops_cb_flags_set(struct bpf_sock_ops *bpf_sock, int argval)
 * 	Description
 * 		Attempt to set the value of the **bpf_sock_ops_cb_flags** field
 * 		for the full TCP socket associated to *bpf_sock_ops* to
 * 		*argval*.
 *
 * 		The primary use of this field is to determine if there should
 * 		be calls to eBPF programs of type
 * 		**BPF_PROG_TYPE_SOCK_OPS** at various points in the TCP
 * 		code. A program of the same type can change its value, per
 * 		connection and as necessary, when the connection is
 * 		established. This field is directly accessible for reading, but
 * 		this helper must be used for updates in order to return an
 * 		error if an eBPF program tries to set a callback that is not
 * 		supported in the current kernel.
 *
 * 		The supported callback values that *argval* can combine are:
 *
 * 		* **BPF_SOCK_OPS_RTO_CB_FLAG** (retransmission time out)
 * 		* **BPF_SOCK_OPS_RETRANS_CB_FLAG** (retransmission)
 * 		* **BPF_SOCK_OPS_STATE_CB_FLAG** (TCP state change)
 *
 * 		Here are some examples of where one could call such eBPF
 * 		program:
 *
 * 		* When RTO fires.
 * 		* When a packet is retransmitted.
 * 		* When the connection terminates.
 * 		* When a packet is sent.
 * 		* When a packet is received.
 * 	Return
 * 		Code **-EINVAL** if the socket is not a full TCP socket;
 * 		otherwise, a positive number containing the bits that could not
 * 		be set is returned (which comes down to 0 if all bits were set
 * 		as required).
 *
 * int bpf_msg_redirect_map(struct sk_msg_buff *msg, struct bpf_map *map, u32 key, u64 flags)
 * 	Description
 * 		This helper is used in programs implementing policies at the
 * 		socket level. If the message *msg* is allowed to pass (i.e. if
 * 		the verdict eBPF program returns **SK_PASS**), redirect it to
 * 		the socket referenced by *map* (of type
 * 		**BPF_MAP_TYPE_SOCKMAP**) at index *key*. Both ingress and
 * 		egress interfaces can be used for redirection. The
 * 		**BPF_F_INGRESS** value in *flags* is used to make the
 * 		distinction (ingress path is selected if the flag is present,
 * 		egress path otherwise). This is the only flag supported for now.
 * 	Return
 * 		**SK_PASS** on success, or **SK_DROP** on error.
 *
 * int bpf_msg_apply_bytes(struct sk_msg_buff *msg, u32 bytes)
 * 	Description
 * 		For socket policies, apply the verdict of the eBPF program to
 * 		the next *bytes* (number of bytes) of message *msg*.
 *
 * 		For example, this helper can be used in the following cases:
 *
 * 		* A single **sendmsg**\ () or **sendfile**\ () system call
 * 		  contains multiple logical messages that the eBPF program is
 * 		  supposed to read and for which it should apply a verdict.
 * 		* An eBPF program only cares to read the first *bytes* of a
 * 		  *msg*. If the message has a large payload, then setting up
 * 		  and calling the eBPF program repeatedly for all bytes, even
 * 		  though the verdict is already known, would create unnecessary
 * 		  overhead.
 *
 * 		When called from within an eBPF program, the helper sets a
 * 		counter internal to the BPF infrastructure, that is used to
 * 		apply the last verdict to the next *bytes*. If *bytes* is
 * 		smaller than the current data being processed from a
 * 		**sendmsg**\ () or **sendfile**\ () system call, the first
 * 		*bytes* will be sent and the eBPF program will be re-run with
 * 		the pointer for start of data pointing to byte number *bytes*
 * 		**+ 1**. If *bytes* is larger than the current data being
 * 		processed, then the eBPF verdict will be applied to multiple
 * 		**sendmsg**\ () or **sendfile**\ () calls until *bytes* are
 * 		consumed.
 *
 * 		Note that if a socket closes with the internal counter holding
 * 		a non-zero value, this is not a problem because data is not
 * 		being buffered for *bytes* and is sent as it is received.
 * 	Return
 * 		0
 *
 * int bpf_msg_cork_bytes(struct sk_msg_buff *msg, u32 bytes)
 * 	Description
 * 		For socket policies, prevent the execution of the verdict eBPF
 * 		program for message *msg* until *bytes* (byte number) have been
 * 		accumulated.
 *
 * 		This can be used when one needs a specific number of bytes
 * 		before a verdict can be assigned, even if the data spans
 * 		multiple **sendmsg**\ () or **sendfile**\ () calls. The extreme
 * 		case would be a user calling **sendmsg**\ () repeatedly with
 * 		1-byte long message segments. Obviously, this is bad for
 * 		performance, but it is still valid. If the eBPF program needs
 * 		*bytes* bytes to validate a header, this helper can be used to
 * 		prevent the eBPF program to be called again until *bytes* have
 * 		been accumulated.
 * 	Return
 * 		0
 *
 * int bpf_msg_pull_data(struct sk_msg_buff *msg, u32 start, u32 end, u64 flags)
 * 	Description
 * 		For socket policies, pull in non-linear data from user space
 * 		for *msg* and set pointers *msg*\ **->data** and *msg*\
 * 		**->data_end** to *start* and *end* bytes offsets into *msg*,
 * 		respectively.
 *
 * 		If a program of type **BPF_PROG_TYPE_SK_MSG** is run on a
 * 		*msg* it can only parse data that the (**data**, **data_end**)
 * 		pointers have already consumed. For **sendmsg**\ () hooks this
 * 		is likely the first scatterlist element. But for calls relying
 * 		on the **sendpage** handler (e.g. **sendfile**\ ()) this will
 * 		be the range (**0**, **0**) because the data is shared with
 * 		user space and by default the objective is to avoid allowing
 * 		user space to modify data while (or after) eBPF verdict is
 * 		being decided. This helper can be used to pull in data and to
 * 		set the start and end pointer to given values. Data will be
 * 		copied if necessary (i.e. if data was not linear and if start
 * 		and end pointers do not point to the same chunk).
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_bind(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len)
 * 	Description
 * 		Bind the socket associated to *ctx* to the address pointed by
 * 		*addr*, of length *addr_len*. This allows for making outgoing
 * 		connection from the desired IP address, which can be useful for
 * 		example when all processes inside a cgroup should use one
 * 		single IP address on a host that has multiple IP configured.
 *
 * 		This helper works for IPv4 and IPv6, TCP and UDP sockets. The
 * 		domain (*addr*\ **->sa_family**) must be **AF_INET** (or
 * 		**AF_INET6**). Looking for a free port to bind to can be
 * 		expensive, therefore binding to port is not permitted by the
 * 		helper: *addr*\ **->sin_port** (or **sin6_port**, respectively)
 * 		must be set to zero.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_xdp_adjust_tail(struct xdp_buff *xdp_md, int delta)
 * 	Description
 * 		Adjust (move) *xdp_md*\ **->data_end** by *delta* bytes. It is
 * 		only possible to shrink the packet as of this writing,
 * 		therefore *delta* must be a negative integer.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_skb_get_xfrm_state(struct sk_buff *skb, u32 index, struct bpf_xfrm_state *xfrm_state, u32 size, u64 flags)
 * 	Description
 * 		Retrieve the XFRM state (IP transform framework, see also
 * 		**ip-xfrm(8)**) at *index* in XFRM "security path" for *skb*.
 *
 * 		The retrieved value is stored in the **struct bpf_xfrm_state**
 * 		pointed by *xfrm_state* and of length *size*.
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		This helper is available only if the kernel was compiled with
 * 		**CONFIG_XFRM** configuration option.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_get_stack(struct pt_regs *regs, void *buf, u32 size, u64 flags)
 * 	Description
 * 		Return a user or a kernel stack in bpf program provided buffer.
 * 		To achieve this, the helper needs *ctx*, which is a pointer
 * 		to the context on which the tracing program is executed.
 * 		To store the stacktrace, the bpf program provides *buf* with
 * 		a nonnegative *size*.
 *
 * 		The last argument, *flags*, holds the number of stack frames to
 * 		skip (from 0 to 255), masked with
 * 		**BPF_F_SKIP_FIELD_MASK**. The next bits can be used to set
 * 		the following flags:
 *
 * 		**BPF_F_USER_STACK**
 * 			Collect a user space stack instead of a kernel stack.
 * 		**BPF_F_USER_BUILD_ID**
 * 			Collect buildid+offset instead of ips for user stack,
 * 			only valid if **BPF_F_USER_STACK** is also specified.
 *
 * 		**bpf_get_stack**\ () can collect up to
 * 		**PERF_MAX_STACK_DEPTH** both kernel and user frames, subject
 * 		to sufficient large buffer size. Note that
 * 		this limit can be controlled with the **sysctl** program, and
 * 		that it should be manually increased in order to profile long
 * 		user stacks (such as stacks for Java programs). To do so, use:
 *
 * 		::
 *
 * 			# sysctl kernel.perf_event_max_stack=<new value>
 * 	Return
 * 		A non-negative value equal to or less than *size* on success,
 * 		or a negative error in case of failure.
 *
 * int bpf_skb_load_bytes_relative(const struct sk_buff *skb, u32 offset, void *to, u32 len, u32 start_header)
 * 	Description
 * 		This helper is similar to **bpf_skb_load_bytes**\ () in that
 * 		it provides an easy way to load *len* bytes from *offset*
 * 		from the packet associated to *skb*, into the buffer pointed
 * 		by *to*. The difference to **bpf_skb_load_bytes**\ () is that
 * 		a fifth argument *start_header* exists in order to select a
 * 		base offset to start from. *start_header* can be one of:
 *
 * 		**BPF_HDR_START_MAC**
 * 			Base offset to load data from is *skb*'s mac header.
 * 		**BPF_HDR_START_NET**
 * 			Base offset to load data from is *skb*'s network header.
 *
 * 		In general, "direct packet access" is the preferred method to
 * 		access packet data, however, this helper is in particular useful
 * 		in socket filters where *skb*\ **->data** does not always point
 * 		to the start of the mac header and where "direct packet access"
 * 		is not available.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags)
 *	Description
 *		Do FIB lookup in kernel tables using parameters in *params*.
 *		If lookup is successful and result shows packet is to be
 *		forwarded, the neighbor tables are searched for the nexthop.
 *		If successful (ie., FIB lookup shows forwarding and nexthop
 *		is resolved), the nexthop address is returned in ipv4_dst
 *		or ipv6_dst based on family, smac is set to mac address of
 *		egress device, dmac is set to nexthop mac address, rt_metric
 *		is set to metric from route (IPv4/IPv6 only), and ifindex
 *		is set to the device index of the nexthop from the FIB lookup.
 *
 *		*plen* argument is the size of the passed in struct.
 *		*flags* argument can be a combination of one or more of the
 *		following values:
 *
 *		**BPF_FIB_LOOKUP_DIRECT**
 *			Do a direct table lookup vs full lookup using FIB
 *			rules.
 *		**BPF_FIB_LOOKUP_OUTPUT**
 *			Perform lookup from an egress perspective (default is
 *			ingress).
 *
 *		*ctx* is either **struct xdp_md** for XDP programs or
 *		**struct sk_buff** tc cls_act programs.
 *	Return
 *		* < 0 if any input argument is invalid
 *		*   0 on success (packet is forwarded, nexthop neighbor exists)
 *		* > 0 one of **BPF_FIB_LKUP_RET_** codes explaining why the
 *		  packet is not forwarded or needs assist from full stack
 *
 * int bpf_sock_hash_update(struct bpf_sock_ops_kern *skops, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		Add an entry to, or update a sockhash *map* referencing sockets.
 *		The *skops* is used as a new value for the entry associated to
 *		*key*. *flags* is one of:
 *
 *		**BPF_NOEXIST**
 *			The entry for *key* must not exist in the map.
 *		**BPF_EXIST**
 *			The entry for *key* must already exist in the map.
 *		**BPF_ANY**
 *			No condition on the existence of the entry for *key*.
 *
 *		If the *map* has eBPF programs (parser and verdict), those will
 *		be inherited by the socket being added. If the socket is
 *		already attached to eBPF programs, this results in an error.
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * int bpf_msg_redirect_hash(struct sk_msg_buff *msg, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		This helper is used in programs implementing policies at the
 *		socket level. If the message *msg* is allowed to pass (i.e. if
 *		the verdict eBPF program returns **SK_PASS**), redirect it to
 *		the socket referenced by *map* (of type
 *		**BPF_MAP_TYPE_SOCKHASH**) using hash *key*. Both ingress and
 *		egress interfaces can be used for redirection. The
 *		**BPF_F_INGRESS** value in *flags* is used to make the
 *		distinction (ingress path is selected if the flag is present,
 *		egress path otherwise). This is the only flag supported for now.
 *	Return
 *		**SK_PASS** on success, or **SK_DROP** on error.
 *
 * int bpf_sk_redirect_hash(struct sk_buff *skb, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		This helper is used in programs implementing policies at the
 *		skb socket level. If the sk_buff *skb* is allowed to pass (i.e.
 *		if the verdeict eBPF program returns **SK_PASS**), redirect it
 *		to the socket referenced by *map* (of type
 *		**BPF_MAP_TYPE_SOCKHASH**) using hash *key*. Both ingress and
 *		egress interfaces can be used for redirection. The
 *		**BPF_F_INGRESS** value in *flags* is used to make the
 *		distinction (ingress path is selected if the flag is present,
 *		egress otherwise). This is the only flag supported for now.
 *	Return
 *		**SK_PASS** on success, or **SK_DROP** on error.
 *
 * int bpf_lwt_push_encap(struct sk_buff *skb, u32 type, void *hdr, u32 len)
 *	Description
 *		Encapsulate the packet associated to *skb* within a Layer 3
 *		protocol header. This header is provided in the buffer at
 *		address *hdr*, with *len* its size in bytes. *type* indicates
 *		the protocol of the header and can be one of:
 *
 *		**BPF_LWT_ENCAP_SEG6**
 *			IPv6 encapsulation with Segment Routing Header
 *			(**struct ipv6_sr_hdr**). *hdr* only contains the SRH,
 *			the IPv6 header is computed by the kernel.
 *		**BPF_LWT_ENCAP_SEG6_INLINE**
 *			Only works if *skb* contains an IPv6 packet. Insert a
 *			Segment Routing Header (**struct ipv6_sr_hdr**) inside
 *			the IPv6 header.
 *		**BPF_LWT_ENCAP_IP**
 *			IP encapsulation (GRE/GUE/IPIP/etc). The outer header
 *			must be IPv4 or IPv6, followed by zero or more
 *			additional headers, up to LWT_BPF_MAX_HEADROOM total
 *			bytes in all prepended headers. Please note that
 *			if skb_is_gso(skb) is true, no more than two headers
 *			can be prepended, and the inner header, if present,
 *			should be either GRE or UDP/GUE.
 *
 *		BPF_LWT_ENCAP_SEG6*** types can be called by bpf programs of
 *		type BPF_PROG_TYPE_LWT_IN; BPF_LWT_ENCAP_IP type can be called
 *		by bpf programs of types BPF_PROG_TYPE_LWT_IN and
 *		BPF_PROG_TYPE_LWT_XMIT.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 *	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_lwt_seg6_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len)
 *	Description
 *		Store *len* bytes from address *from* into the packet
 *		associated to *skb*, at *offset*. Only the flags, tag and TLVs
 *		inside the outermost IPv6 Segment Routing Header can be
 *		modified through this helper.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 *	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_lwt_seg6_adjust_srh(struct sk_buff *skb, u32 offset, s32 delta)
 *	Description
 *		Adjust the size allocated to TLVs in the outermost IPv6
 *		Segment Routing Header contained in the packet associated to
 *		*skb*, at position *offset* by *delta* bytes. Only offsets
 *		after the segments are accepted. *delta* can be as well
 *		positive (growing) as negative (shrinking).
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 *	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_lwt_seg6_action(struct sk_buff *skb, u32 action, void *param, u32 param_len)
 *	Description
 *		Apply an IPv6 Segment Routing action of type *action* to the
 *		packet associated to *skb*. Each action takes a parameter
 *		contained at address *param*, and of length *param_len* bytes.
 *		*action* can be one of:
 *
 *		**SEG6_LOCAL_ACTION_END_X**
 *			End.X action: Endpoint with Layer-3 cross-connect.
 *			Type of *param*: **struct in6_addr**.
 *		**SEG6_LOCAL_ACTION_END_T**
 *			End.T action: Endpoint with specific IPv6 table lookup.
 *			Type of *param*: **int**.
 *		**SEG6_LOCAL_ACTION_END_B6**
 *			End.B6 action: Endpoint bound to an SRv6 policy.
 *			Type of param: **struct ipv6_sr_hdr**.
 *		**SEG6_LOCAL_ACTION_END_B6_ENCAP**
 *			End.B6.Encap action: Endpoint bound to an SRv6
 *			encapsulation policy.
 *			Type of param: **struct ipv6_sr_hdr**.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 *	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_rc_repeat(void *ctx)
 *	Description
 *		This helper is used in programs implementing IR decoding, to
 *		report a successfully decoded repeat key message. This delays
 *		the generation of a key up event for previously generated
 *		key down event.
 *
 *		Some IR protocols like NEC have a special IR message for
 *		repeating last button, for when a button is held down.
 *
 *		The *ctx* should point to the lirc sample as passed into
 *		the program.
 *
 *		This helper is only available is the kernel was compiled with
 *		the **CONFIG_BPF_LIRC_MODE2** configuration option set to
 *		"**y**".
 *	Return
 *		0
 *
 * int bpf_rc_keydown(void *ctx, u32 protocol, u64 scancode, u32 toggle)
 *	Description
 *		This helper is used in programs implementing IR decoding, to
 *		report a successfully decoded key press with *scancode*,
 *		*toggle* value in the given *protocol*. The scancode will be
 *		translated to a keycode using the rc keymap, and reported as
 *		an input key down event. After a period a key up event is
 *		generated. This period can be extended by calling either
 *		**bpf_rc_keydown**\ () again with the same values, or calling
 *		**bpf_rc_repeat**\ ().
 *
 *		Some protocols include a toggle bit, in case the button	was
 *		released and pressed again between consecutive scancodes.
 *
 *		The *ctx* should point to the lirc sample as passed into
 *		the program.
 *
 *		The *protocol* is the decoded protocol number (see
 *		**enum rc_proto** for some predefined values).
 *
 *		This helper is only available is the kernel was compiled with
 *		the **CONFIG_BPF_LIRC_MODE2** configuration option set to
 *		"**y**".
 *	Return
 *		0
 *
 * u64 bpf_skb_cgroup_id(struct sk_buff *skb)
 * 	Description
 * 		Return the cgroup v2 id of the socket associated with the *skb*.
 * 		This is roughly similar to the **bpf_get_cgroup_classid**\ ()
 * 		helper for cgroup v1 by providing a tag resp. identifier that
 * 		can be matched on or used for map lookups e.g. to implement
 * 		policy. The cgroup v2 id of a given path in the hierarchy is
 * 		exposed in user space through the f_handle API in order to get
 * 		to the same 64-bit id.
 *
 * 		This helper can be used on TC egress path, but not on ingress,
 * 		and is available only if the kernel was compiled with the
 * 		**CONFIG_SOCK_CGROUP_DATA** configuration option.
 * 	Return
 * 		The id is returned or 0 in case the id could not be retrieved.
 *
 * u64 bpf_get_current_cgroup_id(void)
 * 	Return
 * 		A 64-bit integer containing the current cgroup id based
 * 		on the cgroup within which the current task is running.
 *
 * void *bpf_get_local_storage(void *map, u64 flags)
 *	Description
 *		Get the pointer to the local storage area.
 *		The type and the size of the local storage is defined
 *		by the *map* argument.
 *		The *flags* meaning is specific for each map type,
 *		and has to be 0 for cgroup local storage.
 *
 *		Depending on the BPF program type, a local storage area
 *		can be shared between multiple instances of the BPF program,
 *		running simultaneously.
 *
 *		A user should care about the synchronization by himself.
 *		For example, by using the **BPF_STX_XADD** instruction to alter
 *		the shared data.
 *	Return
 *		A pointer to the local storage area.
 *
 * int bpf_sk_select_reuseport(struct sk_reuseport_md *reuse, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		Select a **SO_REUSEPORT** socket from a
 *		**BPF_MAP_TYPE_REUSEPORT_ARRAY** *map*.
 *		It checks the selected socket is matching the incoming
 *		request in the socket buffer.
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * u64 bpf_skb_ancestor_cgroup_id(struct sk_buff *skb, int ancestor_level)
 *	Description
 *		Return id of cgroup v2 that is ancestor of cgroup associated
 *		with the *skb* at the *ancestor_level*.  The root cgroup is at
 *		*ancestor_level* zero and each step down the hierarchy
 *		increments the level. If *ancestor_level* == level of cgroup
 *		associated with *skb*, then return value will be same as that
 *		of **bpf_skb_cgroup_id**\ ().
 *
 *		The helper is useful to implement policies based on cgroups
 *		that are upper in hierarchy than immediate cgroup associated
 *		with *skb*.
 *
 *		The format of returned id and helper limitations are same as in
 *		**bpf_skb_cgroup_id**\ ().
 *	Return
 *		The id is returned or 0 in case the id could not be retrieved.
 *
 * struct bpf_sock *bpf_sk_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)
 *	Description
 *		Look for TCP socket matching *tuple*, optionally in a child
 *		network namespace *netns*. The return value must be checked,
 *		and if non-**NULL**, released via **bpf_sk_release**\ ().
 *
 *		The *ctx* should point to the context of the program, such as
 *		the skb or socket (depending on the hook in use). This is used
 *		to determine the base network namespace for the lookup.
 *
 *		*tuple_size* must be one of:
 *
 *		**sizeof**\ (*tuple*\ **->ipv4**)
 *			Look for an IPv4 socket.
 *		**sizeof**\ (*tuple*\ **->ipv6**)
 *			Look for an IPv6 socket.
 *
 *		If the *netns* is a negative signed 32-bit integer, then the
 *		socket lookup table in the netns associated with the *ctx* will
 *		will be used. For the TC hooks, this is the netns of the device
 *		in the skb. For socket hooks, this is the netns of the socket.
 *		If *netns* is any other signed 32-bit value greater than or
 *		equal to zero then it specifies the ID of the netns relative to
 *		the netns associated with the *ctx*. *netns* values beyond the
 *		range of 32-bit integers are reserved for future use.
 *
 *		All values for *flags* are reserved for future usage, and must
 *		be left at zero.
 *
 *		This helper is available only if the kernel was compiled with
 *		**CONFIG_NET** configuration option.
 *	Return
 *		Pointer to **struct bpf_sock**, or **NULL** in case of failure.
 *		For sockets with reuseport option, the **struct bpf_sock**
 *		result is from **reuse->socks**\ [] using the hash of the tuple.
 *
 * struct bpf_sock *bpf_sk_lookup_udp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)
 *	Description
 *		Look for UDP socket matching *tuple*, optionally in a child
 *		network namespace *netns*. The return value must be checked,
 *		and if non-**NULL**, released via **bpf_sk_release**\ ().
 *
 *		The *ctx* should point to the context of the program, such as
 *		the skb or socket (depending on the hook in use). This is used
 *		to determine the base network namespace for the lookup.
 *
 *		*tuple_size* must be one of:
 *
 *		**sizeof**\ (*tuple*\ **->ipv4**)
 *			Look for an IPv4 socket.
 *		**sizeof**\ (*tuple*\ **->ipv6**)
 *			Look for an IPv6 socket.
 *
 *		If the *netns* is a negative signed 32-bit integer, then the
 *		socket lookup table in the netns associated with the *ctx* will
 *		will be used. For the TC hooks, this is the netns of the device
 *		in the skb. For socket hooks, this is the netns of the socket.
 *		If *netns* is any other signed 32-bit value greater than or
 *		equal to zero then it specifies the ID of the netns relative to
 *		the netns associated with the *ctx*. *netns* values beyond the
 *		range of 32-bit integers are reserved for future use.
 *
 *		All values for *flags* are reserved for future usage, and must
 *		be left at zero.
 *
 *		This helper is available only if the kernel was compiled with
 *		**CONFIG_NET** configuration option.
 *	Return
 *		Pointer to **struct bpf_sock**, or **NULL** in case of failure.
 *		For sockets with reuseport option, the **struct bpf_sock**
 *		result is from **reuse->socks**\ [] using the hash of the tuple.
 *
 * int bpf_sk_release(struct bpf_sock *sock)
 *	Description
 *		Release the reference held by *sock*. *sock* must be a
 *		non-**NULL** pointer that was returned from
 *		**bpf_sk_lookup_xxx**\ ().
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * int bpf_map_push_elem(struct bpf_map *map, const void *value, u64 flags)
 * 	Description
 * 		Push an element *value* in *map*. *flags* is one of:
 *
 * 		**BPF_EXIST**
 * 			If the queue/stack is full, the oldest element is
 * 			removed to make room for this.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_map_pop_elem(struct bpf_map *map, void *value)
 * 	Description
 * 		Pop an element from *map*.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_map_peek_elem(struct bpf_map *map, void *value)
 * 	Description
 * 		Get an element from *map* without removing it.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_msg_push_data(struct sk_buff *skb, u32 start, u32 len, u64 flags)
 *	Description
 *		For socket policies, insert *len* bytes into *msg* at offset
 *		*start*.
 *
 *		If a program of type **BPF_PROG_TYPE_SK_MSG** is run on a
 *		*msg* it may want to insert metadata or options into the *msg*.
 *		This can later be read and used by any of the lower layer BPF
 *		hooks.
 *
 *		This helper may fail if under memory pressure (a malloc
 *		fails) in these cases BPF programs will get an appropriate
 *		error and BPF programs will need to handle them.
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * int bpf_msg_pop_data(struct sk_msg_buff *msg, u32 start, u32 pop, u64 flags)
 *	Description
 *		Will remove *pop* bytes from a *msg* starting at byte *start*.
 *		This may result in **ENOMEM** errors under certain situations if
 *		an allocation and copy are required due to a full ring buffer.
 *		However, the helper will try to avoid doing the allocation
 *		if possible. Other errors can occur if input parameters are
 *		invalid either due to *start* byte not being valid part of *msg*
 *		payload and/or *pop* value being to large.
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * int bpf_rc_pointer_rel(void *ctx, s32 rel_x, s32 rel_y)
 *	Description
 *		This helper is used in programs implementing IR decoding, to
 *		report a successfully decoded pointer movement.
 *
 *		The *ctx* should point to the lirc sample as passed into
 *		the program.
 *
 *		This helper is only available is the kernel was compiled with
 *		the **CONFIG_BPF_LIRC_MODE2** configuration option set to
 *		"**y**".
 *	Return
 *		0
 *
 * int bpf_spin_lock(struct bpf_spin_lock *lock)
 *	Description
 *		Acquire a spinlock represented by the pointer *lock*, which is
 *		stored as part of a value of a map. Taking the lock allows to
 *		safely update the rest of the fields in that value. The
 *		spinlock can (and must) later be released with a call to
 *		**bpf_spin_unlock**\ (\ *lock*\ ).
 *
 *		Spinlocks in BPF programs come with a number of restrictions
 *		and constraints:
 *
 *		* **bpf_spin_lock** objects are only allowed inside maps of
 *		  types **BPF_MAP_TYPE_HASH** and **BPF_MAP_TYPE_ARRAY** (this
 *		  list could be extended in the future).
 *		* BTF description of the map is mandatory.
 *		* The BPF program can take ONE lock at a time, since taking two
 *		  or more could cause dead locks.
 *		* Only one **struct bpf_spin_lock** is allowed per map element.
 *		* When the lock is taken, calls (either BPF to BPF or helpers)
 *		  are not allowed.
 *		* The **BPF_LD_ABS** and **BPF_LD_IND** instructions are not
 *		  allowed inside a spinlock-ed region.
 *		* The BPF program MUST call **bpf_spin_unlock**\ () to release
 *		  the lock, on all execution paths, before it returns.
 *		* The BPF program can access **struct bpf_spin_lock** only via
 *		  the **bpf_spin_lock**\ () and **bpf_spin_unlock**\ ()
 *		  helpers. Loading or storing data into the **struct
 *		  bpf_spin_lock** *lock*\ **;** field of a map is not allowed.
 *		* To use the **bpf_spin_lock**\ () helper, the BTF description
 *		  of the map value must be a struct and have **struct
 *		  bpf_spin_lock** *anyname*\ **;** field at the top level.
 *		  Nested lock inside another struct is not allowed.
 *		* The **struct bpf_spin_lock** *lock* field in a map value must
 *		  be aligned on a multiple of 4 bytes in that value.
 *		* Syscall with command **BPF_MAP_LOOKUP_ELEM** does not copy
 *		  the **bpf_spin_lock** field to user space.
 *		* Syscall with command **BPF_MAP_UPDATE_ELEM**, or update from
 *		  a BPF program, do not update the **bpf_spin_lock** field.
 *		* **bpf_spin_lock** cannot be on the stack or inside a
 *		  networking packet (it can only be inside of a map values).
 *		* **bpf_spin_lock** is available to root only.
 *		* Tracing programs and socket filter programs cannot use
 *		  **bpf_spin_lock**\ () due to insufficient preemption checks
 *		  (but this may change in the future).
 *		* **bpf_spin_lock** is not allowed in inner maps of map-in-map.
 *	Return
 *		0
 *
 * int bpf_spin_unlock(struct bpf_spin_lock *lock)
 *	Description
 *		Release the *lock* previously locked by a call to
 *		**bpf_spin_lock**\ (\ *lock*\ ).
 *	Return
 *		0
 *
 * struct bpf_sock *bpf_sk_fullsock(struct bpf_sock *sk)
 *	Description
 *		This helper gets a **struct bpf_sock** pointer such
 *		that all the fields in this **bpf_sock** can be accessed.
 *	Return
 *		A **struct bpf_sock** pointer on success, or **NULL** in
 *		case of failure.
 *
 * struct bpf_tcp_sock *bpf_tcp_sock(struct bpf_sock *sk)
 *	Description
 *		This helper gets a **struct bpf_tcp_sock** pointer from a
 *		**struct bpf_sock** pointer.
 *	Return
 *		A **struct bpf_tcp_sock** pointer on success, or **NULL** in
 *		case of failure.
 *
 * int bpf_skb_ecn_set_ce(struct sk_buf *skb)
 *	Description
 *		Set ECN (Explicit Congestion Notification) field of IP header
 *		to **CE** (Congestion Encountered) if current value is **ECT**
 *		(ECN Capable Transport). Otherwise, do nothing. Works with IPv6
 *		and IPv4.
 *	Return
 *		1 if the **CE** flag is set (either by the current helper call
 *		or because it was already present), 0 if it is not set.
 *
 * struct bpf_sock *bpf_get_listener_sock(struct bpf_sock *sk)
 *	Description
 *		Return a **struct bpf_sock** pointer in **TCP_LISTEN** state.
 *		**bpf_sk_release**\ () is unnecessary and not allowed.
 *	Return
 *		A **struct bpf_sock** pointer on success, or **NULL** in
 *		case of failure.
 */
//#define __BPF_FUNC_MAPPER(FN)		\
//	FN(unspec),			\
//	FN(map_lookup_elem),		\
//	FN(map_update_elem),		\
//	FN(map_delete_elem),		\
//	FN(probe_read),			\
//	FN(ktime_get_ns),		\
//	FN(trace_printk),		\
//	FN(get_prandom_u32),		\
//	FN(get_smp_processor_id),	\
//	FN(skb_store_bytes),		\
//	FN(l3_csum_replace),		\
//	FN(l4_csum_replace),		\
//	FN(tail_call),			\
//	FN(clone_redirect),		\
//	FN(get_current_pid_tgid),	\
//	FN(get_current_uid_gid),	\
//	FN(get_current_comm),		\
//	FN(get_cgroup_classid),		\
//	FN(skb_vlan_push),		\
//	FN(skb_vlan_pop),		\
//	FN(skb_get_tunnel_key),		\
//	FN(skb_set_tunnel_key),		\
//	FN(perf_event_read),		\
//	FN(redirect),			\
//	FN(get_route_realm),		\
//	FN(perf_event_output),		\
//	FN(skb_load_bytes),		\
//	FN(get_stackid),		\
//	FN(csum_diff),			\
//	FN(skb_get_tunnel_opt),		\
//	FN(skb_set_tunnel_opt),		\
//	FN(skb_change_proto),		\
//	FN(skb_change_type),		\
//	FN(skb_under_cgroup),		\
//	FN(get_hash_recalc),		\
//	FN(get_current_task),		\
//	FN(probe_write_user),		\
//	FN(current_task_under_cgroup),	\
//	FN(skb_change_tail),		\
//	FN(skb_pull_data),		\
//	FN(csum_update),		\
//	FN(set_hash_invalid),		\
//	FN(get_numa_node_id),		\
//	FN(skb_change_head),		\
//	FN(xdp_adjust_head),		\
//	FN(probe_read_str),		\
//	FN(get_socket_cookie),		\
//	FN(get_socket_uid),		\
//	FN(set_hash),			\
//	FN(setsockopt),			\
//	FN(skb_adjust_room),		\
//	FN(redirect_map),		\
//	FN(sk_redirect_map),		\
//	FN(sock_map_update),		\
//	FN(xdp_adjust_meta),		\
//	FN(perf_event_read_value),	\
//	FN(perf_prog_read_value),	\
//	FN(getsockopt),			\
//	FN(override_return),		\
//	FN(sock_ops_cb_flags_set),	\
//	FN(msg_redirect_map),		\
//	FN(msg_apply_bytes),		\
//	FN(msg_cork_bytes),		\
//	FN(msg_pull_data),		\
//	FN(bind),			\
//	FN(xdp_adjust_tail),		\
//	FN(skb_get_xfrm_state),		\
//	FN(get_stack),			\
//	FN(skb_load_bytes_relative),	\
//	FN(fib_lookup),			\
//	FN(sock_hash_update),		\
//	FN(msg_redirect_hash),		\
//	FN(sk_redirect_hash),		\
//	FN(lwt_push_encap),		\
//	FN(lwt_seg6_store_bytes),	\
//	FN(lwt_seg6_adjust_srh),	\
//	FN(lwt_seg6_action),		\
//	FN(rc_repeat),			\
//	FN(rc_keydown),			\
//	FN(skb_cgroup_id),		\
//	FN(get_current_cgroup_id),	\
//	FN(get_local_storage),		\
//	FN(sk_select_reuseport),	\
//	FN(skb_ancestor_cgroup_id),	\
//	FN(sk_lookup_tcp),		\
//	FN(sk_lookup_udp),		\
//	FN(sk_release),			\
//	FN(map_push_elem),		\
//	FN(map_pop_elem),		\
//	FN(map_peek_elem),		\
//	FN(msg_push_data),		\
//	FN(msg_pop_data),		\
//	FN(rc_pointer_rel),		\
//	FN(spin_lock),			\
//	FN(spin_unlock),		\
//	FN(sk_fullsock),		\
//	FN(tcp_sock),			\
//	FN(skb_ecn_set_ce),		\
//	FN(get_listener_sock),

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
//#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
//enum bpf_func_id {
//	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
//	__BPF_FUNC_MAX_ID,
//};
//#undef __BPF_ENUM_FN

/// All flags used by eBPF helper functions, placed here.

/// BPF_FUNC_skb_store_bytes flags.
pub const BPF_F_RECOMPUTE_CSUM: i32 = 1 << 0;
pub const BPF_F_INVALIDATE_HASH: i32 = 1 << 1;

/* BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
 * First 4 bits are for passing the header field size.
 */
pub const BPF_F_HDR_FIELD_MASK: i32 = 0xf;

/// BPF_FUNC_l4_csum_replace flags.
pub const BPF_F_PSEUDO_HDR: i32 = 1 << 4;
pub const BPF_F_MARK_MANGLED_0: i32 = 1 << 5;
pub const BPF_F_MARK_ENFORCE: i32 = 1 << 6;

/// BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags.
pub const BPF_F_INGRESS: i32 = 1 << 0;

/// BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags.
pub const BPF_F_TUNINFO_IPV6: i32 = 1 << 0;

/// flags for both BPF_FUNC_get_stackid and BPF_FUNC_get_stack.
pub const BPF_F_SKIP_FIELD_MASK: i32 = 0xff;
pub const BPF_F_USER_STACK: i32 = 1 << 8;

/// flags used by BPF_FUNC_get_stackid only.
pub const BPF_F_FAST_STACK_CMP: i32 = 1 << 9;
pub const BPF_F_REUSE_STACKID: i32 = 1 << 10;
/// flags used by BPF_FUNC_get_stack only.
pub const BPF_F_USER_BUILD_ID: i32 = 1 << 11;

/// BPF_FUNC_skb_set_tunnel_key flags.
pub const BPF_F_ZERO_CSUM_TX: i32 = 1 << 1;
pub const BPF_F_DONT_FRAGMENT: i32 = 1 << 2;
pub const BPF_F_SEQ_NUMBER: i32 = 1 << 3;

/// BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
/// BPF_FUNC_perf_event_read_value flags.
pub const BPF_F_INDEX_MASK: u64 = 0xffffffff;
pub const BPF_F_CURRENT_CPU: u64 = BPF_F_INDEX_MASK;

/// BPF_FUNC_perf_event_output for sk_buff input context.
pub const BPF_F_CTXLEN_MASK: u64 = 0xfffff << 32;

/// Current network namespace
pub const BPF_F_CURRENT_NETNS: i32 = -1;

/// Mode for BPF_FUNC_skb_adjust_room helper.
pub const BPF_ADJ_ROOM_NET: i32 = 0;

/// Mode for BPF_FUNC_skb_load_bytes_relative helper.
pub const BPF_HDR_START_MAC: i32 = 0;
pub const BPF_HDR_START_NET: i32 = 1;

/// Encapsulation type for BPF_FUNC_lwt_push_encap helper.
pub const BPF_LWT_ENCAP_SEG6: i32 = 0;
pub const BPF_LWT_ENCAP_SEG6_INLINE: i32 = 1;
pub const BPF_LWT_ENCAP_IP: i32 = 2;

//#define __bpf_md_ptr(type, name)	\
//union {					\
//	type name;			\
//	__u64 :64;			\
//} __attribute__((aligned(8)))

/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
//struct __sk_buff {
//	__u32 len;
//	__u32 pkt_type;
//	__u32 mark;
//	__u32 queue_mapping;
//	__u32 protocol;
//	__u32 vlan_present;
//	__u32 vlan_tci;
//	__u32 vlan_proto;
//	__u32 priority;
//	__u32 ingress_ifindex;
//	__u32 ifindex;
//	__u32 tc_index;
//	__u32 cb[5];
//	__u32 hash;
//	__u32 tc_classid;
//	__u32 data;
//	__u32 data_end;
//	__u32 napi_id;
//
//	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
//	__u32 family;
//	__u32 remote_ip4;	/* Stored in network byte order */
//	__u32 local_ip4;	/* Stored in network byte order */
//	__u32 remote_ip6[4];	/* Stored in network byte order */
//	__u32 local_ip6[4];	/* Stored in network byte order */
//	__u32 remote_port;	/* Stored in network byte order */
//	__u32 local_port;	/* stored in host byte order */
//	/* ... here. */
//
//	__u32 data_meta;
//	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
//	__u64 tstamp;
//	__u32 wire_len;
//	__u32 gso_segs;
//	__bpf_md_ptr(struct bpf_sock *, sk);
//};

//struct bpf_tunnel_key {
//	__u32 tunnel_id;
//	union {
//		__u32 remote_ipv4;
//		__u32 remote_ipv6[4];
//	};
//	__u8 tunnel_tos;
//	__u8 tunnel_ttl;
//	__u16 tunnel_ext;	/* Padding, future use. */
//	__u32 tunnel_label;
//};

/* user accessible mirror of in-kernel xfrm_state.
 * new fields can only be added to the end of this structure
 */
//struct bpf_xfrm_state {
//	__u32 reqid;
//	__u32 spi;	/* Stored in network byte order */
//	__u16 family;
//	__u16 ext;	/* Padding, future use. */
//	union {
//		__u32 remote_ipv4;	/* Stored in network byte order */
//		__u32 remote_ipv6[4];	/* Stored in network byte order */
//	};
//}

/// Generic BPF return codes which all BPF program types may support.
/// The values are binary compatible with their TC_ACT_* counter-part to
/// provide backwards compatibility with existing SCHED_CLS and SCHED_ACT
/// programs.
///
/// XDP is handled seprately, see XDP_*.
pub const BPF_OK: i32 = 0;
// 1 reserved
pub const BPF_DROP: i32 = 2;
// 3-6 reserved
pub const BPF_REDIRECT: i32 = 7;

/* >127 are reserved for prog type specific return codes.
 *
 * BPF_LWT_REROUTE: used by BPF_PROG_TYPE_LWT_IN and
 *    BPF_PROG_TYPE_LWT_XMIT to indicate that skb had been
 *    changed and should be routed based on its new L3 header.
 *    (This is an L3 redirect, as opposed to L2 redirect
 *    represented by BPF_REDIRECT above).
 */

pub const BPF_LWT_REROUTE: i32 = 128;

#[repr(C)]
pub struct bpf_sock_t {
    pub bound_dev_if: u32,
    pub family: u32,
    pub type_: u32,
    pub protocol: u32,
    pub mark: u32,
    pub priority: u32,
    /// IP address also allows 1 and 2 bytes access
    pub src_ip4: u32,
    pub src_ip6: [u32; 4],
    /// host byte order
    pub src_port: u32,
    /// network byte order
    pub dst_port: u32,
    pub dst_ip4: u32,
    pub dst_ip6: [u32; 4],
    pub state: u32,
}

#[repr(C)]
pub struct bpf_tcp_sock_t {
    /// Sending congestion window
    pub snd_cwnd: u32,
    /// smoothed round trip time << 3 in usecs
    pub srtt_us: u32,
    pub rtt_min: u32,
    /// Slow start size threshold
    pub snd_ssthresh: u32,
    /// What we want to receive next
    pub rcv_nxt: u32,
    /// Next sequence we send
    pub snd_nxt: u32,
    /// First byte we want an ack for
    pub snd_una: u32,
    /// Cached effective mss, not including SACKS
    pub mss_cache: u32,
    /// ECN status bits.
    pub ecn_flags: u32,
    /// saved rate sample: packets delivered
    pub rate_delivered: u32,
    /// saved rate sample: time elapsed
    pub rate_interval_us: u32,
    /// Packets which are "in flight"
    pub packets_out: u32,
    /// Retransmitted packets out
    pub retrans_out: u32,
    /// Total retransmits for entire connection
    pub total_retrans: u32,
    /// RFC4898 tcpEStatsPerfSegsIn total number of segments in
    pub segs_in: u32,
    /// RFC4898 tcpEStatsPerfDataSegsIn total number of data segments in.
    pub data_segs_in: u32,
    /// RFC4898 tcpEStatsPerfSegsOut The total number of segments sent.
    pub segs_out: u32,
    /// RFC4898 tcpEStatsPerfDataSegsOut total number of data segments sent.
    pub data_segs_out: u32,
    /// Lost packets
    pub lost_out: u32,
    /// SACK'd packets
    pub sacked_out: u32,
    /// RFC4898 tcpEStatsAppHCThruOctetsReceived
    /// sum(delta(rcv_nxt)), or how many bytes were acked.
    bytes_received: u64,
    /// RFC4898 tcpEStatsAppHCThruOctetsAcked
    /// sum(delta(snd_una)), or how many bytes were acked.
    pub bytes_acked: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_sock_tuple_ipv4_t {
    pub saddr: be32_t,
    pub daddr: be32_t,
    pub sport: be16_t,
    pub dport: be16_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_sock_tuple_ipv6_t {
    pub saddr: [be32_t; 4],
    pub daddr: [be32_t; 4],
    pub sport: be16_t,
    pub dport: be16_t,
}

#[repr(C)]
pub union bpf_sock_tuple_t {
    pub ipv4: bpf_sock_tuple_ipv4_t,
    pub ipv6: bpf_sock_tuple_ipv6_t,
}

pub const XDP_PACKET_HEADROOM: i32 = 256;

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 */
pub const XDP_ABORTED: i32 = 0;
pub const XDP_DROP: i32 = 1;
pub const XDP_PASS: i32 = 2;
pub const XDP_TX: i32 = 3;
pub const XDP_REDIRECT: i32 = 4;

/// user accessible metadata for XDP packet hook
/// new fields must be added to the end of this structure
#[repr(C)]
pub struct xdp_md_t {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    /// Below access go through struct xdp_rxq_info
    /// rxq->dev->ifindex
    pub ingress_ifindex: u32,
    /// rxq->queue_index  
    pub rx_queue_index: u32,
}

pub const SK_DROP: i32 = 0;
pub const SK_PASS: i32 = 1;

#[repr(C)]
pub union bpf_md_ptr_t {
    pub data: usize,
    _u64: u64,
}

#[repr(C)]
pub union bpf_md_end_ptr_t {
    pub data_end: usize,
    _u64: u64,
}

/// user accessible metadata for SK_MSG packet hook, new fields must
/// be added to the end of this structure
#[repr(C)]
pub struct sk_msg_md_t {
    pub data: bpf_md_ptr_t,
    pub data_end: bpf_md_end_ptr_t,

    pub family: u32,
    /// Stored in network byte order
    pub remote_ip4: u32,
    /// Stored in network byte order
    pub local_ip4: u32,
    /// Stored in network byte order
    pub remote_ip6: [u32; 4],
    /// Stored in network byte order
    pub local_ip6: [u32; 4],
    /// Stored in network byte order
    pub remote_port: u32,
    /// stored in host byte order
    pub local_port: u32,
    /// Total size of sk_msg
    pub size: u32,
}

#[repr(C)]
pub struct sk_reuseport_md_t {
    /// Start of directly accessible data. It begins from the tcp/udp header.
    pub data: bpf_md_ptr_t,
    /// End of directly accessible data
    pub data_end: bpf_md_end_ptr_t,

    /// Total length of packet (starting from the tcp/udp header).
    /// Note that the directly accessible bytes (data_end - data)
    /// could be less than this "len".  Those bytes could be
    /// indirectly read by a helper "bpf_skb_load_bytes()".
    pub len: u32,

    /// Eth protocol in the mac header (network byte order). e.g.
    /// ETH_P_IP(0x0800) and ETH_P_IPV6(0x86DD)
    pub eth_protocol: u32,
    /// IP protocol. e.g. IPPROTO_TCP, IPPROTO_UDP
    pub ip_protocol: u32,
    /// Is sock bound to an INANY address?
    pub bind_inany: u32,
    /// A hash of the packet 4 tuples
    pub hash: u32,
}

pub const BPF_TAG_SIZE: usize = 8;

#[repr(C)]
pub struct bpf_prog_info_t {
    pub type_: u32,
    pub id: u32,
    pub tag: [u8; BPF_TAG_SIZE],
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: u64,
    pub xlated_prog_insns: u64,
    /// ns since boottime
    pub load_time: u64,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: u64,
    pub name: [u8; BPF_OBJ_NAME_LEN],
    pub ifindex: u32,
    //__u32 gpl_compatible:1;
    //TOD(Shaohua): Fix type alignment error
    pub gpl_compatible: u8,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: u64,
    pub jited_func_lens: u64,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: u64,
    pub jited_line_info: u64,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: u64,
    pub run_time_ns: u64,
    pub run_cnt: u64,
}

#[repr(C)]
pub struct bpf_map_info_t {
    pub type_: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: [u8; BPF_OBJ_NAME_LEN],
    pub ifindex: u32,
    //__u32 :32;
    pad: [u8; 32],
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

#[repr(C)]
pub struct bpf_btf_info_t {
    pub btf: u64,
    pub btf_size: u32,
    pub id: u32,
}

/// User bpf_sock_addr struct to access socket fields and sockaddr struct passed
/// by user and intended to be used by socket (e.g. to bind to, depends on
/// attach attach type).
#[repr(C)]
pub struct bpf_sock_addr_t {
    /// Allows 4-byte read, but no write.
    pub user_family: u32,

    /// Allows 1,2,4-byte read and 4-byte write.  Stored in network byte order.
    pub user_ip4: u32,

    /// Allows 1,2,4-byte read an 4-byte write.  Stored in network byte order.
    pub user_ip6: [u32; 4],

    /// Allows 4-byte read and write.  Stored in network byte order
    pub user_port: u32,

    /// Allows 4-byte read, but no write
    pub family: u32,

    /// Allows 4-byte read, but no write
    pub type_: u32,

    /// Allows 4-byte read, but no write
    pub protocol: u32,

    /// Allows 1,2,4-byte read an 4-byte write. Stored in network byte order.
    pub msg_src_ip4: u32,

    /// Allows 1,2,4-byte read an 4-byte write.  Stored in network byte order.
    pub msg_src_ip6: [u32; 4],
}

#[repr(C)]
pub union bpf_sock_ops_reply_t {
    /// Optionally passed to bpf program
    pub args: [u32; 4],

    /// Returned by bpf program	    
    pub reply: u32,

    /* Optionally returned by bpf prog  */
    pub replylong: [u32; 4],
}

/// User bpf_sock_ops struct to access socket values and specify request ops
/// and their replies.
/// Some of this fields are in network (bigendian) byte order and may need
/// to be converted before use (bpf_ntohl() defined in samples/bpf/bpf_endian.h).
/// New fields can only be added at the end of this structure
#[repr(C)]
pub struct bpf_sock_ops_t {
    pub op: u32,
    pub reply: bpf_sock_ops_reply_t,

    pub family: u32,

    /// Stored in network byte order
    pub remote_ip4: u32,

    /// Stored in network byte order
    pub local_ip4: u32,

    /// Stored in network byte order
    pub remote_ip6: [u32; 4],

    /// Stored in network byte order
    pub local_ip6: [u32; 4],

    /// Stored in network byte order
    pub remote_port: u32,

    /// stored in host byte order
    pub local_port: u32,

    /// Some TCP fields are only valid if there is a full socket.
    /// If not, the fields read as zero.
    pub is_fullsock: u32,

    pub snd_cwnd: u32,

    /// Averaged RTT << 3 in usecs
    pub srtt_us: u32,

    /// flags defined in uapi/linux/tcp.h
    pub bpf_sock_ops_cb_flags: u32,

    pub state: u32,
    pub rtt_min: u32,
    pub snd_ssthresh: u32,
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub mss_cache: u32,
    pub ecn_flags: u32,
    pub rate_delivered: u32,
    pub rate_interval_us: u32,
    pub packets_out: u32,
    pub retrans_out: u32,
    pub total_retrans: u32,
    pub segs_in: u32,
    pub data_segs_in: u32,
    pub segs_out: u32,
    pub data_segs_out: u32,
    pub lost_out: u32,
    pub sacked_out: u32,
    pub sk_txhash: u32,
    pub bytes_received: u64,
    pub bytes_acked: u64,
}

/// Definitions for bpf_sock_ops_cb_flags
pub const BPF_SOCK_OPS_RTO_CB_FLAG: i32 = 1 << 0;
pub const BPF_SOCK_OPS_RETRANS_CB_FLAG: i32 = 1 << 1;
pub const BPF_SOCK_OPS_STATE_CB_FLAG: i32 = 1 << 2;
/// Mask of all currently supported cb flags
pub const BPF_SOCK_OPS_ALL_CB_FLAGS: i32 = 0x7;

/// List of known BPF sock_ops operators.
/// New entries can only be added at the end
pub const BPF_SOCK_OPS_VOID: i32 = 0;

/// Should return SYN-RTO value to use or -1 if default value should be used
pub const BPF_SOCK_OPS_TIMEOUT_INIT: i32 = 1;

/// Should return initial advertized window (in packets) or -1 if default
/// value should be used
pub const BPF_SOCK_OPS_RWND_INIT: i32 = 2;

/// Calls BPF program right before an active connection is initialized
pub const BPF_SOCK_OPS_TCP_CONNECT_CB: i32 = 3;

/// Calls BPF program when an active connection is established
pub const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i32 = 4;

/// Calls BPF program when a passive connection is established
pub const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: i32 = 5;

/// If connection's congestion control needs ECN
pub const BPF_SOCK_OPS_NEEDS_ECN: i32 = 6;

/// Get base RTT. The correct value is based on the path and may be
/// dependent on the congestion control algorithm. In general it indicates
/// a congestion threshold. RTTs above this indicate congestion
pub const BPF_SOCK_OPS_BASE_RTT: i32 = 7;

/// Called when an RTO has triggered.
/// Arg1: value of icsk_retransmits
/// Arg2: value of icsk_rto
/// Arg3: whether RTO has expired
pub const BPF_SOCK_OPS_RTO_CB: i32 = 8;

/// Called when skb is retransmitted.
/// Arg1: sequence number of 1st byte
/// Arg2: # segments
/// Arg3: return value of tcp_transmit_skb (0 => success)
pub const BPF_SOCK_OPS_RETRANS_CB: i32 = 9;

/// Called when TCP changes state.
/// Arg1: old_state
/// Arg2: new_state
pub const BPF_SOCK_OPS_STATE_CB: i32 = 10;

/// Called on listen(2), right after socket transition to LISTEN state.
pub const BPF_SOCK_OPS_TCP_LISTEN_CB: i32 = 11;

/// List of TCP states. There is a build check in net/ipv4/tcp.c to detect
/// changes between the TCP and BPF versions. Ideally this should never happen.
/// If it does, we need to add code to convert them before calling
/// the BPF sock_ops function.
pub const BPF_TCP_ESTABLISHED: i32 = 1;
pub const BPF_TCP_SYN_SENT: i32 = 2;
pub const BPF_TCP_SYN_RECV: i32 = 3;
pub const BPF_TCP_FIN_WAIT1: i32 = 4;
pub const BPF_TCP_FIN_WAIT2: i32 = 5;
pub const BPF_TCP_TIME_WAIT: i32 = 6;
pub const BPF_TCP_CLOSE: i32 = 7;
pub const BPF_TCP_CLOSE_WAIT: i32 = 8;
pub const BPF_TCP_LAST_ACK: i32 = 9;
pub const BPF_TCP_LISTEN: i32 = 10;
/// Now a valid state
pub const BPF_TCP_CLOSING: i32 = 11;
pub const BPF_TCP_NEW_SYN_RECV: i32 = 12;
/// Leave at the end!
pub const BPF_TCP_MAX_STATES: i32 = 13;

/// Set TCP initial congestion window
pub const TCP_BPF_IW: i32 = 1001;
/// Set sndcwnd_clamp
pub const TCP_BPF_SNDCWND_CLAMP: i32 = 1002;

#[repr(C)]
pub struct bpf_perf_event_value_t {
    pub counter: u64,
    pub enabled: u64,
    pub running: u64,
}

pub const BPF_DEVCG_ACC_MKNOD: i32 = 1 << 0;
pub const BPF_DEVCG_ACC_READ: i32 = 1 << 1;
pub const BPF_DEVCG_ACC_WRITE: i32 = 1 << 2;

pub const BPF_DEVCG_DEV_BLOCK: i32 = 1 << 0;
pub const BPF_DEVCG_DEV_CHAR: i32 = 1 << 1;

#[repr(C)]
pub struct bpf_cgroup_dev_ctx_t {
    /// access_type encoded as (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*
    pub access_type: u32,
    pub major: u32,
    pub minor: u32,
}

#[repr(C)]
pub struct bpf_raw_tracepoint_args_t {
    pub args: [u64; 0],
}

/// DIRECT:  Skip the FIB rules and go to FIB table associated with device
/// OUTPUT:  Do lookup from egress perspective; default is ingress
pub const BPF_FIB_LOOKUP_DIRECT: i32 = 0;
pub const BPF_FIB_LOOKUP_OUTPUT: i32 = 1;

/// lookup successful
pub const BPF_FIB_LKUP_RET_SUCCESS: i32 = 0;
/// dest is blackholed; can be dropped
pub const BPF_FIB_LKUP_RET_BLACKHOLE: i32 = 1;
/// dest is unreachable; can be dropped
pub const BPF_FIB_LKUP_RET_UNREACHABLE: i32 = 2;
/// dest not allowed; can be dropped
pub const BPF_FIB_LKUP_RET_PROHIBIT: i32 = 3;
/// packet is not forwarded
pub const BPF_FIB_LKUP_RET_NOT_FWDED: i32 = 4;
/// fwding is not enabled on ingress
pub const BPF_FIB_LKUP_RET_FWD_DISABLED: i32 = 5;
/// fwd requires encapsulation
pub const BPF_FIB_LKUP_RET_UNSUPP_LWT: i32 = 6;
/// no neighbor entry for nh
pub const BPF_FIB_LKUP_RET_NO_NEIGH: i32 = 7;
/// fragmentation required to fwd
pub const BPF_FIB_LKUP_RET_FRAG_NEEDED: i32 = 8;

/// inputs to lookup
#[repr(C)]
pub union bpf_fib_lookup_inputs_t {
    /// AF_INET  
    pub tos: u8,

    /// AF_INET6, flow_label + priority
    pub flowinfo: be32_t,

    /// output: metric of fib result (IPv4/IPv6 only)
    pub rt_metric: u32,
}

#[repr(C)]
pub union bpf_fib_lookup_addr_t {
    pub ipv4: be32_t,

    /// in6_addr; network order
    pub ipv6: [u32; 4],
}

#[repr(C)]
pub struct bpf_fib_lookup_t {
    /// input:  network family for lookup (AF_INET, AF_INET6)
    /// output: network family of egress nexthop
    pub family: u8,

    /// set if lookup is to consider L4 data - e.g., FIB rules
    pub l4_protocol: u8,
    pub sport: be16_t,
    pub dport: be16_t,

    /// total length of packet from network header - used for MTU check
    pub tot_len: u16,

    /// input: L3 device index for lookup
    /// output: device index from FIB lookup
    pub ifindex: u32,

    pub inputs: bpf_fib_lookup_inputs_t,

    pub src: bpf_fib_lookup_addr_t,

    /// input to bpf_fib_lookup, ipv{4,6}_dst is destination address in
    /// network header. output: bpf_fib_lookup sets to gateway address
    /// if FIB lookup returns gateway route
    pub dest: bpf_fib_lookup_addr_t,

    /// output
    pub h_vlan_proto: be16_t,
    pub h_vlan_tci: be16_t,
    /// ETH_ALEN
    pub smac: [u8; 6],
    /// ETH_ALEN
    pub dmac: [u8; 6],
}

/// tp name
pub const BPF_FD_TYPE_RAW_TRACEPOINT: i32 = 0;
/// tp name
pub const BPF_FD_TYPE_TRACEPOINT: i32 = 1;
/// (symbol + offset) or addr
pub const BPF_FD_TYPE_KPROBE: i32 = 3;
/// (symbol + offset) or addr
pub const BPF_FD_TYPE_KRETPROBE: i32 = 4;
/// filename + offset
pub const BPF_FD_TYPE_UPROBE: i32 = 5;
/// filename + offset
pub const BPF_FD_TYPE_URETPROBE: i32 = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_flow_keys_ipv4_t {
    pub ipv4_src: be32_t,
    pub ipv4_dst: be32_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_flow_keys_ipv6_t {
    // TODO(Shaohua): use be32_t
    /// in6_addr; network order
    pub ipv6_src: [u32; 4],
    /// in6_addr; network order */
    pub ipv6_dst: [u32; 4],
}

#[repr(C)]
pub union bpf_flow_keys_addr_t {
    pub ipv4: bpf_flow_keys_ipv4_t,
    pub ipv6: bpf_flow_keys_ipv6_t,
}

#[repr(C)]
pub struct bpf_flow_keys_t {
    pub nhoff: u16,
    pub thoff: u16,
    /// ETH_P_* of valid addrs
    pub addr_proto: u16,
    pub is_frag: u8,
    pub is_first_frag: u8,
    pub is_encap: u8,
    pub ip_proto: u8,
    pub n_proto: be16_t,
    pub sport: be16_t,
    pub dport: be16_t,
    pub addr: bpf_flow_keys_addr_t,
}

#[repr(C)]
pub struct bpf_func_info_t {
    pub insn_off: u32,
    pub type_id: u32,
}

// TODO(Shaohua):
//#define BPF_LINE_INFO_LINE_NUM(line_col)	((line_col) >> 10)
//#define BPF_LINE_INFO_LINE_COL(line_col)	((line_col) & 0x3ff)

#[repr(C)]
pub struct bpf_line_info_t {
    pub insn_off: u32,
    pub file_name_off: u32,
    pub line_off: u32,
    pub line_col: u32,
}

#[repr(C)]
pub struct bpf_spin_lock_t {
    val: u32,
}

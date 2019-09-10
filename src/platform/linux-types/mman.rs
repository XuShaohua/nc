/// stack-like segment
pub const MAP_GROWSDOWN: i32 = 0x0100;
/// ETXTBSY
pub const MAP_DENYWRITE: i32 = 0x0800;
/// mark it as an executable
pub const MAP_EXECUTABLE: i32 = 0x1000;
/// pages are locked
pub const MAP_LOCKED: i32 = 0x2000;
/// don't check for reservations
pub const MAP_NORESERVE: i32 = 0x4000;
/// populate (prefault) pagetables
pub const MAP_POPULATE: i32 = 0x8000;
/// do not block on IO
pub const MAP_NONBLOCK: i32 = 0x10000;
/// give out an address that is best suited for process/thread stacks
pub const MAP_STACK: i32 = 0x20000;
/// create a huge page mapping
pub const MAP_HUGETLB: i32 = 0x40000;
/// perform synchronous page faults for the mapping
pub const MAP_SYNC: i32 = 0x80000;

/// Bits [26:31] are reserved, see mman-common.h for MAP_HUGETLB usage
/// lock all current mappings
pub const MCL_CURRENT: i32 = 1;
/// lock all future mappings
pub const MCL_FUTURE: i32 = 2;
/// lock all pages that are faulted in
pub const MCL_ONFAULT: i32 = 4;

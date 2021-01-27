use core::mem::size_of_val;

const SET_BITS: usize = 1024;
#[repr(C)]
#[derive(Clone, Copy)]
struct CPUSet {
    pub bits: [u8; SET_BITS],
}

impl Default for CPUSet {
    fn default() -> Self {
        CPUSet {
            bits: [0; SET_BITS],
        }
    }
}

impl CPUSet {
    pub fn size() -> usize {
        8 * SET_BITS
    }
    pub fn set(&mut self, _pos: usize) {}

    pub fn as_ptr(&self) -> usize {
        &self.bits as *const [u8; 1024] as usize
    }
}

fn main() {
    let mut set = CPUSet::default();
    let ret = nc::sched_setaffinity(0, CPUSet::size(), set.as_ptr());
    println!("ret: {:?}", ret);
    //assert!(ret.is_ok());
}

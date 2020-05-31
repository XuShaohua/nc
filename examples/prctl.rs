
use std::ffi::CString;

pub fn set_process_name(name: &str) -> Result<(), nc::Errno> {
    let process_name = CString::new(name).unwrap();
    let name_ptr = process_name.as_ptr() as usize;
    nc::prctl(nc::PR_SET_NAME, name_ptr, 0, 0, 0).map(|_ret| ())
}

fn main() {
    let process_name = "rust-001";
    println!("pid: {}, process name: {}", nc::getpid(), &process_name);
    set_process_name(process_name).unwrap();
    nc::pause().unwrap();
}
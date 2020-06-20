
fn main() {
    let mut info = nc::sysinfo_t::default();
    let _ = nc::sysinfo(&mut info);

    println!("free mem: {}", info.freeram * info.mem_unit as usize);
    println!("total mem: {}", info.totalram * info.mem_unit as usize);
}
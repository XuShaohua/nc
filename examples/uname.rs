extern crate nc;

fn main() {
    let mut uts = nc::utsname_t::default();

    match nc::uname(&mut uts) {
        Ok(_) => {
            println!("utsname: {:?}", uts);
        }
        Err(errno) => {
            eprintln!("Failed to get uname: {}", errno);
        }
    }
}

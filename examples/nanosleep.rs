
extern crate nc;

fn main() {
    let req = nc::timespec_t{
        tv_sec: 3,
        tv_nsec: 0,
    };
    let mut rem = nc::timespec_t::default();
    println!("Sleep for 5 seconds...");
    nc::nanosleep(&req, &mut rem);
}

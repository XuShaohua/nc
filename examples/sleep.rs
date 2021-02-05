fn main() {
    let t = nc::timespec_t {
        tv_sec: 3,
        tv_nsec: 1000_000,
    };
    let ret = nc::nanosleep(&t, None);
    assert!(ret.is_ok());
}

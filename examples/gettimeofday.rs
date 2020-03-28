fn main() {
    let mut timeval = nc::timeval_t::default();
    let mut timezone = nc::timezone_t::default();
    if let Err(errno) = nc::gettimeofday(&mut timeval, &mut timezone) {
        eprintln!("gettimeofday() failed: {}", nc::strerror(errno));
    } else {
        println!("time: {:+?}", timeval);
    }
}

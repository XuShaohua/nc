fn main() {
    let socket_fd = match nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) {
        Ok(socket_fd) => socket_fd,
        Err(errno) => {
            eprintln!("socket() err: {}", nc::strerror(errno));
            return;
        }
    };
    let interface_name = "lo";
    if let Err(errno) = nc::setsockopt(
        socket_fd,
        nc::SOL_SOCKET,
        nc::SO_BINDTODEVICE,
        interface_name.as_ptr() as usize,
        interface_name.len() as u32,
    ) {
        eprintln!("socket() err: {}", nc::strerror(errno));
    } else {
        println!("Now socket is bind to {}", interface_name);
    }
}

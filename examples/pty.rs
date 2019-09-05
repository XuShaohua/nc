extern crate nc;

fn ptsname(pty_fd: i32) -> Result<String, nc::Errno> {
    println!("ptsname()");
    #[allow(unused_mut)]
    let mut n: i32 = 0;
    let n_ptr = (&mut n) as *mut i32 as usize;
    nc::ioctl(pty_fd, nc::TIOCGPTN, n_ptr)?;
    return Ok(format!("/dev/pts/{}", n));
}

fn unlockpt(pty_fd: i32) -> Result<(), nc::Errno> {
    println!("unlockpt()");
    let u: i32 = 0;
    let u_ptr = &u as *const i32 as usize;
    nc::ioctl(pty_fd, nc::TIOCSPTLCK, u_ptr)
}

fn open_pty() -> Result<(i32, i32), nc::Errno> {
    let pty_fd = nc::open("/dev/ptmx", nc::O_RDWR, 0)?;
    println!("pty_fd: {}", pty_fd);

    let sname = ptsname(pty_fd)?;
    println!("sname: {}", sname);
    unlockpt(pty_fd)?;

    let tty_fd = nc::openat(nc::AT_FDCWD, &sname, nc::O_RDWR | nc::O_NOCTTY, 0)?;
    println!("tty_fd: {}", tty_fd);

    return Ok((pty_fd, tty_fd));
}

fn main() {
    if let Ok((pty, tty)) = open_pty() {
        println!("pty: {}, tty: {}", pty, tty);
    }
}

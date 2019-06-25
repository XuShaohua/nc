
extern crate nc;

fn ptsname(pts_fd: i32) -> String {
    let mut n: i32;
    let n_ptr = n as *mut i32 as usize;
    let _err = nc::ioctl(pts_fd, nc::TIOCGPTN, n_ptr);
    return format!("/dev/pts/{}", n);
}

fn unlockpt(pts_fd: i32) {
    let mut u: i32 = 0;
    let u_ptr = u as *mut i32 as usize;
    let _err = nc::ioctl(pts_fd, nc::TIOCSPTLCK, u_ptr);
}

fn open_pty() {
    let pts_fd = nc::open("/dev/ptmx", nc::O_RDWR, 0)
        .expect("Failed to open file!");

    let sname = ptsname(pts_fd);
    println!("sname: {}", sname);
    unlockpt(pts_fd);

    let t_fd = nc::open(&sname, nc::O_RDWR | nc::O_NOCTTY, 0)
        .expect("Failed to open pty slave");
    println!("t_fd: {}", t_fd);
}

fn main() {
    open_pty();
}

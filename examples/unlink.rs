fn main() {
    let path = std::path::Path::new("/tmp/nc.unlink");
    let _ret = nc::unlink(path);

    let path = std::path::PathBuf::from("/tmp/nc.unlink");
    let _ret = nc::unlink(path);

    let path = "/tmp/nc.unlink";
    let _ret = nc::unlink(path);
}

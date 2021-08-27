fn main() {
    let path = std::path::Path::new("/tmp/nc.unlink");
    let _ret = nc::unlinkat(nc::AT_FDCWD, path, 0);

    let path = std::path::PathBuf::from("/tmp/nc.unlink");
    let _ret = nc::unlinkat(nc::AT_FDCWD, path, 0);

    let path = "/tmp/nc.unlink";
    let _ret = nc::unlinkat(nc::AT_FDCWD, path, 0);
}

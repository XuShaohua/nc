
About
=====

This ci config is used to test non-x86 architectures, based on debian rootfs.


## debian
If cargo package is installed with apt command like:
```bash
sudo apt install cargo
```

environment named `RUSTUP_TOOLCHAIN` is undefined.

We can pass this environment to cargo by hand:
```bash
RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu cargo build
```

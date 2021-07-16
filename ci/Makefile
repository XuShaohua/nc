
cross-all: cross-aarch64 cross-arm cross-i686 cross-mips cross-mips64 \
	cross-mips64el cross-x86_64

cross-aarch64:
	cross build --target aarch64-unknown-linux-gnu
	cross build --target aarch64-unknown-linux-musl

cross-arm:
	cross build --target arm-unknown-linux-gnueabi
	cross build --target arm-unknown-linux-gnueabihf
	cross build --target arm-unknown-linux-musleabi
	cross build --target arm-unknown-linux-musleabihf

cross-armv7:
	cross build --target armv7-unknown-linux-gnueabi
	cross build --target armv7-unknown-linux-gnueabihf
	cross build --target armv7-unknown-linux-musleabi
	cross build --target armv7-unknown-linux-musleabihf

cross-i686:
	cross build --target i686-unknown-linux-gnu
	cross build --target i686-unknown-linux-musl

cross-mips:
	cross build --target mips-unknown-linux-gnu
	cross build --target mips-unknown-linux-musl

cross-mips64:
	cross build --target mips64-unknown-linux-gnuabi64
	cross build --target mips64-unknown-linux-muslabi64

cross-mips64el:
	cross build --target mips64el-unknown-linux-gnuabi64
	cross build --target mips64el-unknown-linux-muslabi64

cross-mipsel:
	cross build --target mipsel-unknown-linux-gnu
	cross build --target mipsel-unknown-linux-musl

cross-powerpc:
	cross build --target powerpc-unknown-linux-gnu

cross-powerpc64:
	cross build --target powerpc64-unknown-linux-gnu

cross-powerpc64le:
	cross build --target powerpc64le-unknown-linux-gnu

#cross-riscv64gc:
#	cross build --target riscv64gc-unknown-linux-gnu

cross-s390x:
	cross build --target s390x-unknown-linux-gnu

#cross-sparc64:
#	cross build --target sparc64-unknown-linux-gnu

#cross-thumbv7neon:
#	cross build --target thumbv7neon-unknown-linux-gnueabihf

cross-x86_64:
	cross build --target x86_64-unknown-linux-gnu
	cross build --target x86_64-unknown-linux-gnux32
	cross build --target x86_64-unknown-linux-musl


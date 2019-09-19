
install-host-deps:
	sudo apt update
	sudo apt install debootstrap qemu-user-static

# TODO(Shaohua): Add mirror url env
install-rootfs:
	for arch in arm64 armel armhf i386 mips mipsel mips64el ppc64el s390x; do \
		sudo debootstrap --arch $${arch} --include=gcc,vim,python3,wget \
		  buster root-$${arch} http://ftp.cn.debian.org/debian \
	done

mount-fs:
	sudo mount -t proc proc ./proc
	sudo mount -t sysfs sysfs ./sys
	sudo mount --bind /dev ./dev
	sudo mount -t devpts devps ./dev/pts
	sudo mount --bind .. ./opt

umount-fs:
	sudo umount ./proc ./dev/pts ./sys ./opt
	sudo umount ./dev
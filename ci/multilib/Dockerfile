
FROM debian:buster

LABEL MAINTAINER = "Xu Shaohua<shaohua@biofan.org>"
LABEL DESCRIPTION = "Debian multilib environment for nc build"

RUN echo "deb http://mirrors.huaweicloud.com/debian buster main" > /etc/apt/sources.list
RUN apt update
RUN apt install -y vim wget gcc ca-certificates less python3 python3-pip

# Download rustup
RUN wget https://sh.rustup.rs -O rustup-init.sh
RUN RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup \
    RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static \
    bash rustup-init.sh --default-toolchain stable -y

COPY config /root/.cargo/config

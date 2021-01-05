// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
  int epfd = epoll_create1(EPOLL_CLOEXEC);
  assert(epfd > -1);
  struct epoll_event event;
  int fd = STDIN_FILENO;
  event.data.fd = fd;
  event.events = EPOLLIN | EPOLLET;
  int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
  if (ret != 0) {
    perror("epoll_ctl()");
  }
  assert(ret == 0);
  close(epfd);

  return 0;
}

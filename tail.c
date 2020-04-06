// Copyright (C) 2020 bas smit
// SPDX-License-Identifier:  GPL-2.0-or-later

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "kernel/nfs_trace.h"

#define CPUS 2

int has_exit_sig = 0;

void sig_handler(int sig_num) { has_exit_sig = 1; }

int opendev(int id) {
  char buf[64] = {0};

  if (snprintf(buf, 64, "/dev/nfs_trace%d", id) < 0) {
    return -1;
  }

  return open(buf, O_RDONLY);
}

int read_events(int fd) {
  uint64_t count = 0;
  char buf[8192];
  int ret = read(fd, buf, 8192);
  if (ret < 0) {
    perror("Failed to read event");
    return 0;
  }

  for (int i = 0; i < ret; i += sizeof(nt_event_t)) {
    nt_event_t *event = (nt_event_t *)(buf + i);
    printf("%c:%s\n", event->type, event->path);
    count++;
  }

  return count;
}

int loop(int *fds, size_t count) {
  size_t errcount = 0;
  uint64_t events = 0;
  struct pollfd *pollfds = malloc(sizeof(struct pollfd) * count);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  signal(SIGHUP, sig_handler);

  for (int i = 0; i < count; i++) {
    pollfds[i].fd = fds[i];
    pollfds[i].events = POLLIN;
  }

  while (errcount < 10 && !has_exit_sig) {
    if (poll(pollfds, count, -1) < 0) {
      if (errno == EINTR && has_exit_sig)
        goto exit;

      perror("Poll failed");
      errcount++;
    }
    for (int i = 0; i < count; i++) {
      if (pollfds[i].revents)
        events += read_events(pollfds[i].fd);
    }
  }

exit:
  free(pollfds);
  return events;
}

int main(void) {
  int fds[CPUS];
  int events = 0;

  for (int i = 0; i < CPUS; i++) {
    int fd = opendev(i);
    if (fd < 0) {
      char buf[64] = {0};
      snprintf(buf, 64, "Failed to open nfs_trace%d", i);
      perror(buf);
      return 1;
    }
    fds[i] = fd;
  }

  events = loop(fds, CPUS);
  fprintf(stderr, "Handled events: %d\n", events);

  for (int i = 0; i < CPUS; i++) {
    uint64_t dropped, events;
    ioctl(fds[i], NT_IOC_DROPPED, &dropped);
    ioctl(fds[i], NT_IOC_EVENTS, &events);
    fprintf(stderr, "Events  on cpu %d: %ld\n", i, events);
    fprintf(stderr, "Dropped on cpu %d: %ld\n", i, dropped);
    close(fds[i]);
  }

  return 0;
}

/*
    Copyright (C) 2007-2009 Proxmox Server Solutions GmbH

    Copyright: vzdump is under GNU GPL, the GNU General Public License.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 dated June, 1991.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the
    Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
    MA 02110-1301, USA.

    Author: Dietmar Maurer <dietmar@proxmox.com>

*/

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

/* Set a signal handler */
static void 
setsig (struct sigaction *sa, int sig, void (*fun)(int), int flags)
{
  sa->sa_handler = fun;
  sa->sa_flags = flags;
  sigemptyset(&sa->sa_mask);
  sigaction(sig, sa, NULL);
}

int
block_is_zero (char const *buffer, size_t size)
{
  while (size--)
    if (*buffer++)
      return 0;

  return 1;
}

ssize_t 
safe_read(int fd, char *buf, size_t count)
{
  ssize_t n;

  do {
    n = read(fd, buf, count);
  } while (n < 0 && errno == EINTR);

  return n;
}

int 
full_read(int fd, char *buf, size_t len)
{
  ssize_t n;
  size_t total;

  total = 0;

  while (len > 0) {
    n = safe_read(fd, buf, len);

    if (n == 0)
	    return total;

    if (n < 0)
	    break;

    buf += n;
    total += n;
    len -= n;
  }

  if (len) {
	  fprintf (stderr, "ERROR: incomplete read detected\n");
	  exit (-1);
  }

  return total;
}

ssize_t 
safe_write(int fd, char *buf, size_t count)
{
  ssize_t n;

  do {
    n = write(fd, buf, count);
  } while (n < 0 && errno == EINTR);

  return n;
}

int 
full_write(int fd, char *buf, size_t len)
{
  ssize_t n;
  size_t total;

  total = 0;

  while (len > 0) {
    n = safe_write(fd, buf, len);

    if (n < 0)
      break;

    buf += n;
    total += n;
    len -= n;
  }

  if (len) {
    fprintf (stderr, "ERROR: incomplete write detected\n");
    exit (-1);
  }

  return total;
}

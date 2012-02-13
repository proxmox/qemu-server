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
#include <time.h>
#include <stdint.h>
#include <getopt.h>
#include <signal.h>

#include "utils.c"

#define BLOCKSIZE 512*8

static char *outname;

static void 
cleanup (void)
{
  if (outname) 
    unlink (outname);
}

void term_handler()
{
  fprintf (stderr, "received signal - terminate process\n");
  exit(-1);
}

size_t
sparse_cp (int infd, int outfd) 
{
  size_t total = 0;
  size_t count;
  char buffer[BLOCKSIZE];
  int last_write_made_hole = 0;

  while ((count = safe_read (infd, buffer, sizeof (buffer))) > 0) {
    if (block_is_zero (buffer, count)) {

      if (lseek (outfd, count, SEEK_CUR) < 0) {
	perror ("cannot lseek\n");
	exit (-1);
      }
      last_write_made_hole = 1;
    } else {
      full_write (outfd, buffer, count);
      last_write_made_hole = 0;
    }
    total += count;
  }

  if (last_write_made_hole) {
    if (ftruncate (outfd, total) < 0) {
      perror ("cannot ftruncate\n");
      exit (-1);
    }
  }

  return total;
}

int
main (int argc, char **argv)
{
  struct sigaction sa;

  if (argc != 2) {
    fprintf (stderr, "wrong number of arguments\n");
    exit (-1);
  }

  time_t starttime = time(NULL);

  outname = argv[1];

  int outfd;

  if ((outfd = open(outname, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1) {
    fprintf (stderr, "unable to open file '%s' - %s\n", 
	     outname, strerror (errno));
    exit (-1);
  }
  atexit(cleanup);

  setsig(&sa, SIGINT, term_handler, SA_RESTART);
  setsig(&sa, SIGQUIT, term_handler, SA_RESTART);
  setsig(&sa, SIGTERM, term_handler, SA_RESTART);
  setsig(&sa, SIGPIPE, term_handler, SA_RESTART);

  size_t total = sparse_cp (0, outfd);

  close (outfd);

  time_t delay = time(NULL) - starttime;
  if (delay <= 0) delay = 1;

  fprintf (stderr, "%zu bytes copied, %zd s, %.2f MiB/s\n", total, delay,
	   (total/(1024*1024))/(float)delay);

  outname = NULL;

  exit (0);
}

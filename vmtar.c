/*
    Copyright (C) 2007-2012 Proxmox Server Solutions GmbH

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

    NOTE: the tar specific code is copied from the GNU tar package (just 
    slighly modified to fit our needs).
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


#define BLOCKSIZE 512
#define BUFFER_BLOCKS 32

static char *outname;

struct writebuffer 
{
  int fd;
  char buffer[BUFFER_BLOCKS*BLOCKSIZE];
  size_t bpos;
  size_t total;
};

/* OLDGNU_MAGIC uses both magic and version fields, which are contiguous. */
#define OLDGNU_MAGIC "ustar  "	/* 7 chars and a null */

struct posix_header
{				/* byte offset */
  char name[100];		/*   0 */
  char mode[8];			/* 100 */
  char uid[8];			/* 108 */
  char gid[8];			/* 116 */
  char size[12];		/* 124 */
  char mtime[12];		/* 136 */
  char chksum[8];		/* 148 */
  char typeflag;		/* 156 */
  char linkname[100];		/* 157 */
  char magic[6];		/* 257 */
  char version[2];		/* 263 */
  char uname[32];		/* 265 */
  char gname[32];		/* 297 */
  char devmajor[8];		/* 329 */
  char devminor[8];		/* 337 */
  char prefix[155];		/* 345 */
				/* 500 */
};

struct sparse
{				/* byte offset */
  char offset[12];		/*   0 */
  char numbytes[12];		/*  12 */
				/*  24 */
};

struct oldgnu_header
{				/* byte offset */
  char unused_pad1[345];	/*   0 */
  char atime[12];		/* 345 Incr. archive: atime of the file */
  char ctime[12];		/* 357 Incr. archive: ctime of the file */
  char offset[12];		/* 369 Multivolume archive: the offset of
				   the start of this volume */
  char longnames[4];		/* 381 Not used */
  char unused_pad2;		/* 385 */
  struct sparse sp[4];
				/* 386 */
  char isextended;		/* 482 Sparse file: Extension sparse header
				   follows */
  char realsize[12];		/* 483 Sparse file: Real size*/
				/* 495 */
};

struct sparse_header
{				/* byte offset */
  struct sparse sp[21]; 	/*   0 */
  char isextended;		/* 504 */
				/* 505 */
};

union block
{
  char buffer[BLOCKSIZE];
  struct posix_header header;
  struct oldgnu_header oldgnu_header;
  struct sparse_header sparse_header;
};


struct sp_entry
{
  off_t offset;
  size_t bytes;
};

struct sp_array {
  size_t real_size;
  size_t effective_size;
  size_t avail; 
  size_t size; 
  struct sp_entry *map;
};

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

struct sp_array*
sparray_new (void) {
  struct sp_array *ma = malloc (sizeof (struct sp_array));
  if (!ma) {
    fprintf (stderr, "ERROR: memory allocation failure\n"); 
    exit (-1);
  }
  ma->real_size = 0;
  ma->effective_size = 0;
  ma->avail = 0; 
  ma->size = 1024; 
  ma->map = malloc (ma->size * sizeof (struct sp_entry));
  if (!ma->map) {
    fprintf (stderr, "ERROR: memory allocation failure\n"); 
    exit (-1);
  }
  return ma;
}

void
sparray_resize (struct sp_array *ma)
{
  ma->size += 1024;
  if (!(ma->map = realloc (ma->map, ma->size * sizeof (struct sp_entry)))) {
    fprintf (stderr, "ERROR: memory allocation failure\n"); 
    exit (-1);
  } 
}

void
sparray_add (struct sp_array *ma, off_t offset, size_t bytes)
{
	
  if (ma->avail == ma->size) {
    sparray_resize(ma);
  }
  ma->map[ma->avail].offset = offset;
  ma->map[ma->avail].bytes = bytes;
  ma->avail++;
}

static void
to_base256 (uintmax_t value, char *where, size_t size)
{
  uintmax_t v = value;
  size_t i = size - 1;

  where[0] = 1 << 7;

  do {
    where[i--] = v & ((1 << 8) - 1);
    v >>= 8;
  } while (i);
}

static void
to_octal (uintmax_t value, char *where, size_t size)
{
  uintmax_t v = value;
  size_t i = size - 1;

  where[i] = '\0';
  do {
    where[--i] = '0' + (v & ((1 << 3) - 1));
    v >>= 3;
  } while (i);
}

/* The maximum uintmax_t value that can be represented with DIGITS digits,
   assuming that each digit is BITS_PER_DIGIT wide.  */
#define MAX_VAL_WITH_DIGITS(digits, bits_per_digit) \
   ((digits) * (bits_per_digit) < sizeof (uintmax_t) * 8 \
    ? ((uintmax_t) 1 << ((digits) * (bits_per_digit))) - 1 \
    : (uintmax_t) -1)

/* The maximum uintmax_t value that can be represented with octal
   digits and a trailing NUL in BUFFER.  */
#define MAX_OCTAL_VAL(buffer) MAX_VAL_WITH_DIGITS (sizeof (buffer) - 1, 3)

void
off12_to_chars (char *p, off_t v)
{
  if (v < 0) {
    fprintf (stderr, "ERROR: internal error - got negative offset\n");
    exit (-1);
  }

  uintmax_t value = (uintmax_t) v;

  if (value <= MAX_VAL_WITH_DIGITS (11, 3)) {
    to_octal (value, p, 12);
  } else {
    to_base256 (value, p, 12);
  }
}

char *
buffer_block(struct writebuffer *wbuf)
{
  size_t space = sizeof (wbuf->buffer) - wbuf->bpos;
  char *blk;

  if (space >= BLOCKSIZE) {
    blk = wbuf->buffer + wbuf->bpos;
    wbuf->bpos += BLOCKSIZE;
  } else {
    full_write (wbuf->fd, wbuf->buffer, wbuf->bpos);
    wbuf->total += wbuf->bpos;
    wbuf->bpos = BLOCKSIZE;
    blk = wbuf->buffer;
  }
  return blk;
}

struct writebuffer*
buffer_new(int fd)
{
  struct writebuffer *wbuf = calloc (1, sizeof (struct writebuffer));

  if (!wbuf) {
    fprintf (stderr, "ERROR: memory allocation failure\n"); 
    exit (-1);
  }

  wbuf->fd = fd;

  return wbuf;
}

void
buffer_flush(struct writebuffer *wbuf)
{
  full_write (wbuf->fd, wbuf->buffer, wbuf->bpos);
  wbuf->total += wbuf->bpos;
  wbuf->bpos = 0;
}

void
dump_header (struct writebuffer *wbuf, const char *filename, time_t mtime, struct sp_array *ma)
{
  union block *blk = (union block *)buffer_block (wbuf);
  memset (blk->buffer, 0, BLOCKSIZE);
  
  if (strlen(filename)>98) {
    fprintf (stderr, "ERROR: filename '%s' too long\n", filename); 
    exit (-1);
  }

  strncpy (blk->header.name, filename, 100);

  sprintf (blk->header.mode, "%07o", 0644);
  sprintf (blk->header.uid, "%07o", 0);
  sprintf (blk->header.gid, "%07o", 0);
  off12_to_chars (blk->header.mtime, mtime);

  memcpy (blk->header.chksum, "        ", 8);

  blk->header.typeflag = ma->avail ? 'S' : '0';
  
  sprintf (blk->header.magic, "%s", OLDGNU_MAGIC);

  sprintf (blk->header.uname, "%s", "root");
  sprintf (blk->header.gname, "%s", "root");

  size_t ind = 0;
  if (ind < ma->avail) {
    size_t i;
    for (i = 0;i < 4 && ind < ma->avail; i++, ind++) {
      off12_to_chars (blk->oldgnu_header.sp[i].offset, ma->map[ind].offset);
      off12_to_chars (blk->oldgnu_header.sp[i].numbytes, ma->map[ind].bytes);
    }
  }

  if (ma->avail > 4)
    blk->oldgnu_header.isextended = 1;

  off12_to_chars (blk->header.size, ma->effective_size);
  off12_to_chars (blk->oldgnu_header.realsize, ma->real_size);

  int sum = 0;
  char *p = blk->buffer;
  int i;
  for (i = BLOCKSIZE; i-- != 0; )
    sum += 0xFF & *p++;

  sprintf (blk->header.chksum, "%6o", sum);

  while (ind < ma->avail) {
    blk = (union block *)buffer_block (wbuf);
    memset (blk->buffer, 0, BLOCKSIZE);
    size_t i;
    for (i = 0;i < 21 && ind < ma->avail; i++, ind++) {
      off12_to_chars (blk->sparse_header.sp[i].offset, ma->map[ind].offset);
      off12_to_chars (blk->sparse_header.sp[i].numbytes, ma->map[ind].bytes);
    }
    if (ind < ma->avail)
      blk->sparse_header.isextended = 1;

  }
}

int
scan_sparse_file (int fd, struct sp_array *ma)
{
  char buffer[BLOCKSIZE];
  size_t count;
  off_t offset = 0;
  off_t file_size = 0;
  size_t sp_bytes = 0;
  off_t sp_offset = 0;

  if (lseek (fd, 0, SEEK_SET) < 0)
    return 0;

  while ((count = full_read (fd, buffer, sizeof (buffer))) > 0) {
    if (block_is_zero (buffer, count)) {
      if (sp_bytes) {
	sparray_add (ma, sp_offset, sp_bytes);
	sp_bytes = 0;
      }
    } else {
      file_size += count;
      if (!sp_bytes)
	sp_offset = offset;
      sp_bytes += count;
    }
    offset += count;
  }

  if (sp_bytes == 0)
    sp_offset = offset;

  sparray_add (ma, sp_offset, sp_bytes);

  ma->real_size = offset;
  ma->effective_size = file_size;

  return 1;
}

int
dump_sparse_file (int fd, struct writebuffer *wbuf, struct sp_array *ma)
{
  if (lseek (fd, 0, SEEK_SET) < 0)
    return 0;

  int i;
  size_t dumped_size = 0;
  for (i = 0; i < ma->avail; i++) {
    struct sp_entry *e = &ma->map[i];
    if (lseek (fd, e->offset, SEEK_SET) < 0)
      return 0;

    off_t bytes_left = e->bytes;

    while (bytes_left > 0) {
      size_t bufsize = (bytes_left > BLOCKSIZE) ? BLOCKSIZE : bytes_left;
      ssize_t bytes_read;

      char *blkbuf = buffer_block (wbuf);
      if ((bytes_read = full_read (fd, blkbuf, bufsize)) < 0) {
	return 0;
      }

      if (!bytes_read) {
	fprintf (stderr, "ERROR: got unexpected EOF\n");
	return 0;
      }

      memset (blkbuf + bytes_read, 0, BLOCKSIZE - bytes_read);

      dumped_size += bytes_read;

      bytes_left -= bytes_read;
    }
  }

  return 1;
}

int
main (int argc, char **argv)
{
  struct sigaction sa;
  int sparse = 0;

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"sparse", 0, 0, 's'},
      {"output", 1, 0, 'o'},
      {0, 0, 0, 0}
    };

    char c = getopt_long (argc, argv, "so:", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 's':
      sparse = 1;
      break;
    case 'o':
      outname = optarg;
      break;
    default:
      fprintf (stderr, "?? getopt returned character code 0%o ??\n", c);
      exit (-1);
    }
  }

  int numargs = argc - optind;
  if (numargs <= 0 || (numargs % 2)) {
      fprintf (stderr, "wrong number of arguments\n");
      exit (-1);
  }

  time_t starttime = time(NULL);

  int outfd;

  if (outname) {
    if ((outfd = open(outname, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1) {
      fprintf (stderr, "unable to open archive '%s' - %s\n", 
	       outname, strerror (errno));
      exit (-1);
    }
    atexit(cleanup);
  } else {
    outfd = fileno (stdout);
  }

  setsig(&sa, SIGINT, term_handler, SA_RESTART);
  setsig(&sa, SIGQUIT, term_handler, SA_RESTART);
  setsig(&sa, SIGTERM, term_handler, SA_RESTART);
  setsig(&sa, SIGPIPE, term_handler, SA_RESTART);

  int saved_optind = optind;
  while (optind < argc) {
    char *source = argv[optind];
    optind += 2;
    struct stat fs;

    if (stat (source, &fs) != 0) {
      fprintf (stderr, "unable to read '%s' - %s\n", 
	       source, strerror (errno));
      exit (-1);
    }

    if (!(S_ISREG(fs.st_mode) || S_ISBLK(fs.st_mode))) {
      fprintf (stderr, "unable to read '%s' - not a file or block device\n", 
	       source);
      exit (-1);      
    }
  }

  optind = saved_optind;

  struct writebuffer *wbuf = buffer_new (outfd);

  while (optind < argc) {
    char *source = argv[optind++];
    char *archivename = argv[optind++];

    int fd;

    fprintf (stderr, "adding '%s' to archive ('%s')\n", source, archivename);

    if ((fd = open(source, O_RDONLY)) == -1) {
      fprintf (stderr, "unable to open '%s' - %s\n", 
	       source, strerror (errno));
      exit (-1);
    }

    struct stat fs;

    if (fstat (fd, &fs) != 0) {
      fprintf (stderr, "unable to stat '%s' - %s\n", 
	       source, strerror (errno));
      exit (-1);
    }

    time_t ctime = fs.st_mtime;

    struct sp_array *ma = sparray_new();
    if (sparse && !S_ISBLK(fs.st_mode)) {
      if (!scan_sparse_file (fd, ma)) {
	fprintf (stderr, "scanning '%s' failed\n", source); 
	exit (-1);
      }
    } else {
      off_t file_size = lseek(fd, 0, SEEK_END);
      if (file_size < 0) {
	fprintf (stderr, "unable to get file size of '%s'\n", source); 
	exit (-1);
      }
      sparray_add (ma, 0, file_size);
      ma->real_size = file_size;
      ma->effective_size = file_size;
    }

    dump_header (wbuf, archivename, ctime, ma);

    if (!dump_sparse_file (fd, wbuf, ma)) {
      fprintf (stderr, "writing '%s' to archive failed\n", source); 
      exit (-1);
    }

    free (ma);

    close (fd);

  }

  // write tar end
  char *buf = buffer_block (wbuf);
  memset (buf, 0, BLOCKSIZE);
  buf = buffer_block (wbuf);
  memset (buf, 0, BLOCKSIZE);

  buffer_flush (wbuf);

  close (outfd);

  time_t delay = time(NULL) - starttime;
  if (delay <= 0) delay = 1;

  fprintf (stderr, "Total bytes written: %zu (%.2f MiB/s)\n", wbuf->total,
	   (wbuf->total/(1024*1024))/(float)delay);

  outname = NULL;

  exit (0);
}

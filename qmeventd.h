/*

    Copyright (C) 2018 Proxmox Server Solutions GmbH

    Copyright: qemumonitor is under GNU GPL, the GNU General Public License.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 dated June, 1991.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
    02111-1307, USA.

    Author: Dominik Csapak <d.csapak@proxmox.com>
*/

#define VERBOSE_PRINT(...) do { if (verbose) { printf(__VA_ARGS__); } } while (0)

static inline void log_neg(int errval, const char *msg)
{
    if (errval < 0) {
	perror(msg);
    }
}

static inline void bail_neg(int errval, const char *msg)
{
    if (errval < 0) {
	perror(msg);
	exit(EXIT_FAILURE);
    }
}

struct Client {
    char buf[4096];
    char vmid[16];
    int fd;
    pid_t pid;
    unsigned int buflen;
    unsigned short graceful;
    unsigned short guest;
};

void handle_qmp_handshake(struct Client *client);
void handle_qmp_event(struct Client *client, struct json_object *obj);
void handle_client(struct Client *client);
void add_new_client(int client_fd);
void cleanup_client(struct Client *client);

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

typedef enum {
    CLIENT_NONE,
    CLIENT_QEMU,
    CLIENT_VZDUMP
} ClientType;

typedef enum {
    STATE_HANDSHAKE,
    STATE_IDLE,
    STATE_EXPECT_STATUS_RESP,
    STATE_TERMINATING
} ClientState;

struct Client {
    char buf[4096];
    unsigned int buflen;

    int fd;
    pid_t pid;

    ClientType type;
    ClientState state;

    // only relevant for type=CLIENT_QEMU
    struct {
        char vmid[16];
        unsigned short graceful;
        unsigned short guest;
        bool term_check_queued;
        bool backup;
    } qemu;

    // only relevant for type=CLIENT_VZDUMP
    struct {
        // vmid of referenced backup
        char vmid[16];
    } vzdump;
};

void handle_qmp_handshake(struct Client *client);
void handle_qmp_event(struct Client *client, struct json_object *obj);
void handle_qmp_return(struct Client *client, struct json_object *data, bool error);
void handle_vzdump_handshake(struct Client *client, struct json_object *data);
void handle_client(struct Client *client);
void add_new_client(int client_fd);
void cleanup_client(struct Client *client);
void terminate_client(struct Client *client);
void terminate_check(struct Client *client);

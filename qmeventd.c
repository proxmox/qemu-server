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

    qmeventd listens on a given socket, and waits for qemu processes
    to connect

    it then waits for shutdown events followed by the closing of the socket,
    it then calls /usr/sbin/qm cleanup with following arguments

    /usr/sbin/qm cleanup VMID <graceful> <guest>

    parameter explanation:

    graceful:
    1|0 depending if it saw a shutdown event before the socket closed

    guest:
    1|0 depending if the shutdown was requested from the guest

*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <json.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "qmeventd.h"

static int verbose = 0;
static int epoll_fd = 0;
static const char *progname;
/*
 * Helper functions
 */

static void
usage()
{
    fprintf(stderr, "Usage: %s [-f] [-v] PATH\n", progname);
    fprintf(stderr, "  -f       run in foreground (default: false)\n");
    fprintf(stderr, "  -v       verbose (default: false)\n");
    fprintf(stderr, "  PATH     use PATH for socket\n");
}

static pid_t
get_pid_from_fd(int fd)
{
    struct ucred credentials = { .pid = 0, .uid = 0, .gid = 0 };
    socklen_t len = sizeof(struct ucred);
    log_neg(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &len), "getsockopt");
    return credentials.pid;
}

/*
 * reads the vmid from /proc/<pid>/cmdline
 * after the '-id' argument
 */
static unsigned long
get_vmid_from_pid(pid_t pid)
{
    char filename[32] = { 0 };
    int len = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (len < 0) {
	fprintf(stderr, "error during snprintf for %d: %s\n", pid,
		strerror(errno));
	return 0;
    }
    if ((size_t)len >= sizeof(filename)) {
	fprintf(stderr, "error: pid %d too long\n", pid);
	return 0;
    }
    FILE *fp = fopen(filename, "re");
    if (fp == NULL) {
	fprintf(stderr, "error opening %s: %s\n", filename, strerror(errno));
	return 0;
    }

    unsigned long vmid = 0;
    ssize_t rc = 0;
    char *buf = NULL;
    size_t buflen = 0;
    while ((rc = getdelim(&buf, &buflen, '\0', fp)) >= 0) {
	if (!strcmp(buf, "-id")) {
	    break;
	}
    }

    if (rc < 0) {
	goto err;
    }

    if (getdelim(&buf, &buflen, '\0', fp) >= 0) {
	if (buf[0] == '-' || buf[0] == '\0') {
	    fprintf(stderr, "invalid vmid %s\n", buf);
	    goto ret;
	}

	errno = 0;
	char *endptr = NULL;
	vmid = strtoul(buf, &endptr, 10);
	if (errno != 0) {
	    vmid = 0;
	    goto err;
	} else if (*endptr != '\0') {
	    fprintf(stderr, "invalid vmid %s\n", buf);
	    vmid = 0;
	}

	goto ret;
    }

err:
    fprintf(stderr, "error parsing vmid for %d: %s\n", pid, strerror(errno));

ret:
    free(buf);
    fclose(fp);
    return vmid;
}

static bool
must_write(int fd, const char *buf, size_t len)
{
    ssize_t wlen;
    do {
	wlen = write(fd, buf, len);
    } while (wlen < 0 && errno == EINTR);

    return (wlen == (ssize_t)len);
}

/*
 * qmp handling functions
 */

void
handle_qmp_handshake(struct Client *client)
{
    VERBOSE_PRINT("%s: got QMP handshake\n", client->vmid);
    static const char qmp_answer[] = "{\"execute\":\"qmp_capabilities\"}\n";
    if (!must_write(client->fd, qmp_answer, sizeof(qmp_answer) - 1)) {
	fprintf(stderr, "%s: cannot complete handshake\n", client->vmid);
	cleanup_client(client);
    }
}

void
handle_qmp_event(struct Client *client, struct json_object *obj)
{
    struct json_object *event;
    if (!json_object_object_get_ex(obj, "event", &event)) {
	return;
    }
    VERBOSE_PRINT("%s: got QMP event: %s\n", client->vmid,
		  json_object_get_string(event));
    // event, check if shutdown and get guest parameter
    if (!strcmp(json_object_get_string(event), "SHUTDOWN")) {
	client->graceful = 1;
	struct json_object *data;
	struct json_object *guest;
	if (json_object_object_get_ex(obj, "data", &data) &&
	    json_object_object_get_ex(data, "guest", &guest))
	{
	    client->guest = (unsigned short)json_object_get_boolean(guest);
	}
    }
}

/*
 * client management functions
 */

void
add_new_client(int client_fd)
{
    struct Client *client = calloc(sizeof(struct Client), 1);
    client->fd = client_fd;
    client->pid = get_pid_from_fd(client_fd);
    if (client->pid == 0) {
	fprintf(stderr, "could not get pid from client\n");
	goto err;
    }
    unsigned long vmid = get_vmid_from_pid(client->pid);
    int res = snprintf(client->vmid, sizeof(client->vmid), "%lu", vmid);
    if (vmid == 0 || res < 0 || res >= (int)sizeof(client->vmid)) {
	fprintf(stderr, "could not get vmid from pid %d\n", client->pid);
	goto err;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = client;
    res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
    if (res < 0) {
	perror("epoll_ctl client add");
	goto err;
    }

    VERBOSE_PRINT("added new client, pid: %d, vmid: %s\n", client->pid,
		client->vmid);

    return;
err:
    (void)close(client_fd);
    free(client);
}

void
cleanup_client(struct Client *client)
{
    VERBOSE_PRINT("%s: client exited, status: graceful: %d, guest: %d\n",
		  client->vmid, client->graceful, client->guest);
    log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL), "epoll del");
    (void)close(client->fd);

    unsigned short graceful = client->graceful;
    unsigned short guest = client->guest;
    char vmid[sizeof(client->vmid)];
    strncpy(vmid, client->vmid, sizeof(vmid));
    free(client);
    VERBOSE_PRINT("%s: executing cleanup\n", vmid);

    int pid = fork();
    if (pid < 0) {
	fprintf(stderr, "fork failed: %s\n", strerror(errno));
	return;
    }
    if (pid == 0) {
	char *script = "/usr/sbin/qm";

	char *args[] = {
	    script,
	    "cleanup",
	    vmid,
	    graceful ? "1" : "0",
	    guest    ? "1" : "0",
	    NULL
	};

	execvp(script, args);
	perror("execvp");
	_exit(1);
    }
}

void
handle_client(struct Client *client)
{
    VERBOSE_PRINT("%s: entering handle\n", client->vmid);
    ssize_t len;
    do {
	len = read(client->fd, (client->buf+client->buflen),
		   sizeof(client->buf) - client->buflen);
    } while (len < 0 && errno == EINTR);

    if (len < 0) {
	if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
	    log_neg((int)len, "read");
	    cleanup_client(client);
	}
	return;
    } else if (len == 0) {
	VERBOSE_PRINT("%s: got EOF\n", client->vmid);
	cleanup_client(client);
	return;
    }

    VERBOSE_PRINT("%s: read %ld bytes\n", client->vmid, len);
    client->buflen += len;

    struct json_tokener *tok = json_tokener_new();
    struct json_object *jobj = NULL;
    enum json_tokener_error jerr = json_tokener_success;
    while (jerr == json_tokener_success && client->buflen != 0) {
	jobj = json_tokener_parse_ex(tok, client->buf, (int)client->buflen);
	jerr = json_tokener_get_error(tok);
	unsigned int offset = (unsigned int)tok->char_offset;
	switch (jerr) {
	    case json_tokener_success:
		// move rest from buffer to front
		memmove(client->buf, client->buf + offset, client->buflen - offset);
		client->buflen -= offset;
		if (json_object_is_type(jobj, json_type_object)) {
		    struct json_object *obj;
		    if (json_object_object_get_ex(jobj, "QMP", &obj)) {
			handle_qmp_handshake(client);
		    } else if (json_object_object_get_ex(jobj, "event", &obj)) {
			handle_qmp_event(client, jobj);
		    } // else ignore message
		}
		break;
	    case json_tokener_continue:
		if (client->buflen >= sizeof(client->buf)) {
		    VERBOSE_PRINT("%s, msg too large, discarding buffer\n",
				  client->vmid);
		    memset(client->buf, 0, sizeof(client->buf));
		    client->buflen = 0;
		} // else we have enough space try again after next read
		break;
	    default:
		VERBOSE_PRINT("%s: parse error: %d, discarding buffer\n",
			      client->vmid, jerr);
		memset(client->buf, 0, client->buflen);
		client->buflen = 0;
		break;
	}
	json_object_put(jobj);
    }
    json_tokener_free(tok);
}


int
main(int argc, char *argv[])
{
    int opt;
    int daemonize = 1;
    char *socket_path = NULL;
    progname = argv[0];

    while ((opt = getopt(argc, argv, "hfv")) != -1) {
	switch (opt) {
	    case 'f':
		daemonize = 0;
		break;
	    case 'v':
		verbose = 1;
		break;
	    case 'h':
		usage();
		exit(EXIT_SUCCESS);
		break;
	    default:
		usage();
		exit(EXIT_FAILURE);
	}
    }

    if (optind >= argc) {
	usage();
	exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);

    socket_path = argv[optind];

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    bail_neg(sock, "socket");

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    unlink(socket_path);
    bail_neg(bind(sock, (struct sockaddr*)&addr, sizeof(addr)), "bind");

    struct epoll_event ev, events[1];
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    bail_neg(epoll_fd, "epoll_create1");

    ev.events = EPOLLIN;
    ev.data.fd = sock;
    bail_neg(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev), "epoll_ctl");

    bail_neg(listen(sock, 10), "listen");

    if (daemonize) {
	bail_neg(daemon(0, 1), "daemon");
    }

    int nevents;

    for(;;) {
	nevents = epoll_wait(epoll_fd, events, 1, -1);
	if (nevents < 0 && errno == EINTR) {
	    // signal happened, try again
	    continue;
	}
	bail_neg(nevents, "epoll_wait");

	for (int n = 0; n < nevents; n++) {
	    if (events[n].data.fd == sock) {

		int conn_sock = accept4(sock, NULL, NULL,
					SOCK_NONBLOCK | SOCK_CLOEXEC);
		log_neg(conn_sock, "accept");
		if (conn_sock > -1) {
		    add_new_client(conn_sock);
		}
	    } else {
		handle_client((struct Client *)events[n].data.ptr);
	    }
	}
    }
}

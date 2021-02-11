// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    Copyright (C) 2018 - 2021 Proxmox Server Solutions GmbH

    Author: Dominik Csapak <d.csapak@proxmox.com>
    Author: Stefan Reiter <s.reiter@proxmox.com>

    Description:

    qmeventd listens on a given socket, and waits for qemu processes to
    connect. After accepting a connection qmeventd waits for shutdown events
    followed by the closing of the socket. Once that happens `qm cleanup` will
    be executed with following three arguments:
    VMID <graceful> <guest>
    Where `graceful` can be `1` or `0` depending if shutdown event was observed
    before the socket got closed. The second parameter `guest` is also boolean
    `1` or `0` depending if the shutdown was requested from the guest OS
    (i.e., the "inside").
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <gmodule.h>
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
GHashTable *vm_clients; // key=vmid (freed on remove), value=*Client (free manually)
GSList *forced_cleanups;
volatile sig_atomic_t alarm_triggered = 0;

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

static void
send_qmp_cmd(struct Client *client, const char *buf, size_t len)
{
    if (!must_write(client->fd, buf, len - 1)) {
	fprintf(stderr, "%s: cannot send QMP message\n", client->qemu.vmid);
	cleanup_client(client);
    }
}

void
handle_qmp_handshake(struct Client *client)
{
    VERBOSE_PRINT("pid%d: got QMP handshake, assuming QEMU client\n", client->pid);

    // extract vmid from cmdline, now that we know it's a QEMU process
    unsigned long vmid = get_vmid_from_pid(client->pid);
    int res = snprintf(client->qemu.vmid, sizeof(client->qemu.vmid), "%lu", vmid);
    if (vmid == 0 || res < 0 || res >= (int)sizeof(client->qemu.vmid)) {
	fprintf(stderr, "could not get vmid from pid %d\n", client->pid);
	cleanup_client(client);
	return;
    }

    VERBOSE_PRINT("pid%d: assigned VMID: %s\n", client->pid, client->qemu.vmid);
    client->type = CLIENT_QEMU;
    if(!g_hash_table_insert(vm_clients, strdup(client->qemu.vmid), client)) {
	// not fatal, just means backup handling won't work
	fprintf(stderr, "%s: could not insert client into VMID->client table\n",
		client->qemu.vmid);
    }

    static const char qmp_answer[] = "{\"execute\":\"qmp_capabilities\"}\n";
    send_qmp_cmd(client, qmp_answer, sizeof(qmp_answer));
}

void
handle_qmp_event(struct Client *client, struct json_object *obj)
{
    struct json_object *event;
    if (!json_object_object_get_ex(obj, "event", &event)) {
	return;
    }
    VERBOSE_PRINT("%s: got QMP event: %s\n", client->qemu.vmid, json_object_get_string(event));

    if (client->state == STATE_TERMINATING) {
	// QEMU sometimes sends a second SHUTDOWN after SIGTERM, ignore
	VERBOSE_PRINT("%s: event was after termination, ignoring\n", client->qemu.vmid);
	return;
    }

    // event, check if shutdown and get guest parameter
    if (!strcmp(json_object_get_string(event), "SHUTDOWN")) {
	client->qemu.graceful = 1;
	struct json_object *data;
	struct json_object *guest;
	if (json_object_object_get_ex(obj, "data", &data) &&
	    json_object_object_get_ex(data, "guest", &guest))
	{
	    client->qemu.guest = (unsigned short)json_object_get_boolean(guest);
	}

	// check if a backup is running and kill QEMU process if not
	terminate_check(client);
    }
}

void
terminate_check(struct Client *client)
{
    if (client->state != STATE_IDLE) {
	// if we're already in a request, queue this one until after
	VERBOSE_PRINT("%s: terminate_check queued\n", client->qemu.vmid);
	client->qemu.term_check_queued = true;
	return;
    }

    client->qemu.term_check_queued = false;

    VERBOSE_PRINT("%s: query-status\n", client->qemu.vmid);
    client->state = STATE_EXPECT_STATUS_RESP;
    static const char qmp_req[] = "{\"execute\":\"query-status\"}\n";
    send_qmp_cmd(client, qmp_req, sizeof(qmp_req));
}

void
handle_qmp_return(struct Client *client, struct json_object *data, bool error)
{
    if (error) {
        const char *msg = "n/a";
        struct json_object *desc;
        if (json_object_object_get_ex(data, "desc", &desc)) {
            msg = json_object_get_string(desc);
        }
        fprintf(stderr, "%s: received error from QMP: %s\n",
                client->qemu.vmid, msg);
        client->state = STATE_IDLE;
        goto out;
    }

    struct json_object *status;
    json_bool has_status = data &&
	json_object_object_get_ex(data, "status", &status);

    bool active = false;
    if (has_status) {
	const char *status_str = json_object_get_string(status);
	active = status_str &&
	    (!strcmp(status_str, "running") || !strcmp(status_str, "paused"));
    }

    switch (client->state) {
	case STATE_EXPECT_STATUS_RESP:
	    client->state = STATE_IDLE;
	    if (active) {
		VERBOSE_PRINT("%s: got status: VM is active\n", client->qemu.vmid);
	    } else if (!client->qemu.backup) {
		terminate_client(client);
	    } else {
		// if we're in a backup, don't do anything, vzdump will notify
		// us when the backup finishes
		VERBOSE_PRINT("%s: not active, but running backup - keep alive\n",
			      client->qemu.vmid);
	    }
	    break;

	// this means we received the empty return from our handshake answer
	case STATE_HANDSHAKE:
	    client->state = STATE_IDLE;
	    VERBOSE_PRINT("%s: QMP handshake complete\n", client->qemu.vmid);
	    break;

	case STATE_IDLE:
	case STATE_TERMINATING:
	    VERBOSE_PRINT("%s: spurious return value received\n",
			  client->qemu.vmid);
	    break;
    }

out:
    if (client->qemu.term_check_queued) {
	terminate_check(client);
    }
}

/*
 * VZDump specific client functions
 */

void
handle_vzdump_handshake(struct Client *client, struct json_object *data)
{
    client->state = STATE_IDLE;

    struct json_object *vmid_obj;
    json_bool has_vmid = data && json_object_object_get_ex(data, "vmid", &vmid_obj);

    if (!has_vmid) {
	VERBOSE_PRINT("pid%d: invalid vzdump handshake: no vmid\n",
		      client->pid);
	return;
    }

    const char *vmid_str = json_object_get_string(vmid_obj);

    if (!vmid_str) {
	VERBOSE_PRINT("pid%d: invalid vzdump handshake: vmid is not a string\n",
		      client->pid);
	return;
    }

    int res = snprintf(client->vzdump.vmid, sizeof(client->vzdump.vmid), "%s", vmid_str);
    if (res < 0 || res >= (int)sizeof(client->vzdump.vmid)) {
	VERBOSE_PRINT("pid%d: invalid vzdump handshake: vmid too long or invalid\n",
		      client->pid);
	return;
    }

    struct Client *vmc =
	(struct Client*) g_hash_table_lookup(vm_clients, client->vzdump.vmid);
    if (vmc) {
	vmc->qemu.backup = true;

	// only mark as VZDUMP once we have set everything up, otherwise 'cleanup'
	// might try to access an invalid value
	client->type = CLIENT_VZDUMP;
	VERBOSE_PRINT("%s: vzdump backup started\n",
		      client->vzdump.vmid);
    } else {
	VERBOSE_PRINT("%s: vzdump requested backup start for unregistered VM\n",
		      client->vzdump.vmid);
    }
}

/*
 * client management functions
 */

void
add_new_client(int client_fd)
{
    struct Client *client = calloc(sizeof(struct Client), 1);
    if (client == NULL) {
	fprintf(stderr, "could not add new client - allocation failed!\n");
	fflush(stderr);
	return;
    }
    client->state = STATE_HANDSHAKE;
    client->type = CLIENT_NONE;
    client->fd = client_fd;
    client->pid = get_pid_from_fd(client_fd);
    if (client->pid == 0) {
	fprintf(stderr, "could not get pid from client\n");
	goto err;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = client;
    int res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
    if (res < 0) {
	perror("epoll_ctl client add");
	goto err;
    }

    VERBOSE_PRINT("added new client, pid: %d\n", client->pid);

    return;
err:
    (void)close(client_fd);
    free(client);
}

static void
cleanup_qemu_client(struct Client *client)
{
    unsigned short graceful = client->qemu.graceful;
    unsigned short guest = client->qemu.guest;
    char vmid[sizeof(client->qemu.vmid)];
    strncpy(vmid, client->qemu.vmid, sizeof(vmid));
    g_hash_table_remove(vm_clients, &vmid); // frees key, ignore errors
    VERBOSE_PRINT("%s: executing cleanup (graceful: %d, guest: %d)\n",
		vmid, graceful, guest);

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
cleanup_client(struct Client *client)
{
    log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL), "epoll del");
    (void)close(client->fd);

    struct Client *vmc;
    switch (client->type) {
	case CLIENT_QEMU:
	    cleanup_qemu_client(client);
	    break;

	case CLIENT_VZDUMP:
	    vmc = (struct Client*) g_hash_table_lookup(vm_clients, client->vzdump.vmid);
	    if (vmc) {
		VERBOSE_PRINT("%s: backup ended\n", client->vzdump.vmid);
		vmc->qemu.backup = false;
		terminate_check(vmc);
	    }
	    break;

	case CLIENT_NONE:
	    // do nothing, only close socket
	    break;
    }

    free(client);
}

void
terminate_client(struct Client *client)
{
    VERBOSE_PRINT("%s: terminating client (pid %d)\n",
		  client->qemu.vmid, client->pid);

    client->state = STATE_TERMINATING;

    // open a pidfd before kill for later cleanup
    int pidfd = pidfd_open(client->pid, 0);
    if (pidfd < 0) {
	switch (errno) {
	    case ESRCH:
		// process already dead for some reason, cleanup done
		VERBOSE_PRINT("%s: failed to open pidfd, process already dead (pid %d)\n",
			      client->qemu.vmid, client->pid);
		return;

	    // otherwise fall back to just using the PID directly, but don't
	    // print if we only failed because we're running on an older kernel
	    case ENOSYS:
		break;
	    default:
		perror("failed to open QEMU pidfd for cleanup");
		break;
	}
    }

    int err = kill(client->pid, SIGTERM);
    log_neg(err, "kill");

    struct CleanupData *data_ptr = malloc(sizeof(struct CleanupData));
    struct CleanupData data = {
	.pid = client->pid,
	.pidfd = pidfd
    };
    *data_ptr = data;
    forced_cleanups = g_slist_prepend(forced_cleanups, (void *)data_ptr);

    // resets any other alarms, but will fire eventually and cleanup all
    alarm(5);
}

void
handle_client(struct Client *client)
{
    VERBOSE_PRINT("pid%d: entering handle\n", client->pid);
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
	VERBOSE_PRINT("pid%d: got EOF\n", client->pid);
	cleanup_client(client);
	return;
    }

    VERBOSE_PRINT("pid%d: read %ld bytes\n", client->pid, len);
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
		    } else if (json_object_object_get_ex(jobj, "return", &obj)) {
			handle_qmp_return(client, obj, false);
		    } else if (json_object_object_get_ex(jobj, "error", &obj)) {
			handle_qmp_return(client, obj, true);
		    } else if (json_object_object_get_ex(jobj, "vzdump", &obj)) {
			handle_vzdump_handshake(client, obj);
		    } // else ignore message
		}
		break;
	    case json_tokener_continue:
		if (client->buflen >= sizeof(client->buf)) {
		    VERBOSE_PRINT("pid%d: msg too large, discarding buffer\n", client->pid);
		    memset(client->buf, 0, sizeof(client->buf));
		    client->buflen = 0;
		} // else we have enough space try again after next read
		break;
	    default:
		VERBOSE_PRINT("pid%d: parse error: %d, discarding buffer\n", client->pid, jerr);
		memset(client->buf, 0, client->buflen);
		client->buflen = 0;
		break;
	}
	json_object_put(jobj);
    }
    json_tokener_free(tok);
}


/*
 * SIGALRM and cleanup handling
 *
 * terminate_client will set an alarm for 5 seconds and add its client's PID to
 * the forced_cleanups list - when the timer expires, we iterate the list and
 * attempt to issue SIGKILL to all processes which haven't yet stopped.
 */

static void
alarm_handler(__attribute__((unused)) int signum)
{
    alarm_triggered = 1;
}

static void
sigkill(void *ptr, __attribute__((unused)) void *unused)
{
    struct CleanupData data = *((struct CleanupData *)ptr);
    int err;

    if (data.pidfd > 0) {
	err = pidfd_send_signal(data.pidfd, SIGKILL, NULL, 0);
	(void)close(data.pidfd);
    } else {
	err = kill(data.pid, SIGKILL);
    }

    if (err < 0) {
	if (errno != ESRCH) {
	    fprintf(stderr, "SIGKILL cleanup of pid '%d' failed - %s\n",
		    data.pid, strerror(errno));
	}
    } else {
	fprintf(stderr, "cleanup failed, terminating pid '%d' with SIGKILL\n",
		data.pid);
    }
}

static void
handle_forced_cleanup()
{
    if (alarm_triggered) {
	VERBOSE_PRINT("clearing forced cleanup backlog\n");
	alarm_triggered = 0;
	g_slist_foreach(forced_cleanups, sigkill, NULL);
	g_slist_free_full(forced_cleanups, free);
	forced_cleanups = NULL;
    }
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
    signal(SIGALRM, alarm_handler);

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

    vm_clients = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);

    int nevents;

    for(;;) {
	nevents = epoll_wait(epoll_fd, events, 1, -1);
	if (nevents < 0 && errno == EINTR) {
	    handle_forced_cleanup();
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

	handle_forced_cleanup();
    }
}

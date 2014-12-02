/*
 * tcprelay.c - TCP relay
 *
 * Copyright (C) 2014, Xiaoxiao <i@xiaoxiao.im>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ev.h>
#include "log.h"
#include "mem.h"

// 缓冲区大小
#define BUF_SIZE 65536

struct
{
	char addr[64];
	socklen_t addrlen;
	int family;
} local, remote;

// connection control block
typedef struct
{
	int sock_local;
	int sock_remote;
	ssize_t tx_bytes;
	ssize_t rx_bytes;
	ev_io w_local_read;
	ev_io w_local_write;
	ev_io w_remote_read;
	ev_io w_remote_write;
	char rx_buf[BUF_SIZE];
	char tx_buf[BUF_SIZE];
} conncb_t;


static void sigint_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void connect_cb(EV_P_ ev_io *w, int revents);
static void local_read_cb(EV_P_ ev_io *w, int revents);
static void local_write_cb(EV_P_ ev_io *w, int revents);
static void remote_read_cb(EV_P_ ev_io *w, int revents);
static void remote_write_cb(EV_P_ ev_io *w, int revents);
static bool setnonblock(int sock);


int main(int argc, char **argv)
{
	if (argc < 5)
	{
		printf("Usage: %s local_host local_port remote_host remote_port\n\n"
			   "Examples:\n"
			   "%s 127.0.0.1 5353 8.8.8.8 53\n", argv[0], argv[0]);
		return 0;
	}

	// 从 arg 中获取 socket 地址
	struct addrinfo hints;
	struct addrinfo *res;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(argv[1], argv[2], &hints, &res) != 0)
	{
		LOG("wrong local_host/local_port");
		return 1;
	}
	memcpy(local.addr, res->ai_addr, res->ai_addrlen);
	local.addrlen = res->ai_addrlen;
	local.family = res->ai_family;
	freeaddrinfo(res);
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(argv[3], argv[4], &hints, &res) != 0)
	{
		LOG("wrong remote_host /remote_port");
		return 1;
	}
	memcpy(remote.addr, res->ai_addr, res->ai_addrlen);
	remote.addrlen = res->ai_addrlen;
	remote.family = res->ai_family;
	freeaddrinfo(res);

	// 初始化 socket
	int sock_listen = socket(local.family, SOCK_STREAM, IPPROTO_TCP);
	if (sock_listen < 0)
	{
		ERR("socket");
		return 2;
	}
	if (!setnonblock(sock_listen))
	{
		return 2;
	}
	int sockopt = 1;
	if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int)) != 0)
	{
		ERR("setsockopt SO_REUSEADDR");
		return 2;
	}
	if (bind(sock_listen, (struct sockaddr *)local.addr, local.addrlen) != 0)
	{
		ERR("bind");
		return 2;
	}
	if (listen(sock_listen, 1024) != 0)
	{
		ERR("listen");
		return 2;
	}

	// 初始化内存池
	size_t block_size[1] = { sizeof(conncb_t) };
	size_t block_count[1] = { 64 };
	if (!mem_init(block_size, block_count, 1))
	{
		LOG("memory pool error");
		return 3;
	}

	// 初始化 ev
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal w_sigint;
	ev_signal_init(&w_sigint, sigint_cb, SIGINT);
	ev_signal_start(loop, &w_sigint);
	ev_io w_listen;
	ev_io_init(&w_listen, accept_cb, sock_listen, EV_READ);
	ev_io_start(loop, &w_listen);

	// 执行事件循环
	LOG("Starting tcprelay...");
	ev_run(loop, 0);

	// 退出
	LOG("Exit");

	return 0;
}

static void sigint_cb(EV_P_ ev_signal *w, int revents)
{
	LOG("SIGINT");
	ev_break(EV_A_ EVBREAK_ALL);
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	LOG("local connection established");

	conncb_t *conn = (conncb_t *)mem_new(sizeof(conncb_t));
	if (conn == NULL)
	{
		return;
	}
	conn->sock_local = accept(w->fd, NULL, NULL);
	if (conn->sock_local < 0)
	{
		ERR("accept");
		mem_delete(conn);
		return;
	}
	if (!setnonblock(conn->sock_local))
	{
		close(conn->sock_local);
		mem_delete(conn);
		return;
	}
	conn->sock_remote = socket(remote.family, SOCK_STREAM, IPPROTO_TCP);
	if (conn->sock_remote < 0)
	{
		ERR("socket");
		close(conn->sock_local);
		mem_delete(conn);
		return;
	}
	if (!setnonblock(conn->sock_remote))
	{
		close(conn->sock_local);
		close(conn->sock_remote);
		mem_delete(conn);
		return;
	}
	ev_io_init(&conn->w_remote_write, connect_cb, conn->sock_remote, EV_WRITE);
	conn->w_remote_write.data = (void *)conn;
	ev_io_start(EV_A_ &conn->w_remote_write);
	connect(conn->sock_remote, (struct sockaddr *)remote.addr, remote.addrlen);
}

static void connect_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conncb_t *conn = (conncb_t *)(w->data);
	int error = 0;
	socklen_t len = sizeof(int);

	getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (error != 0)
	{
		__log(stderr, "connect: %s", strerror(error));
		close(conn->sock_local);
		close(conn->sock_remote);
		mem_delete(conn);
		return;
	}
	LOG("remote connection established");

	ev_io_init(&conn->w_local_read, local_read_cb, conn->sock_local, EV_READ);
	ev_io_init(&conn->w_local_write, local_write_cb, conn->sock_local, EV_WRITE);
	ev_io_init(&conn->w_remote_read, remote_read_cb, conn->sock_remote, EV_READ);
	ev_io_init(&conn->w_remote_write, remote_write_cb, conn->sock_remote, EV_WRITE);
	conn->w_local_read.data = (void *)conn;
	conn->w_local_write.data = (void *)conn;
	conn->w_remote_read.data = (void *)conn;
	conn->w_remote_write.data = (void *)conn;

	ev_io_start(EV_A_ &conn->w_local_read);
	ev_io_start(EV_A_ &conn->w_remote_read);
}

static void local_read_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conncb_t *conn = (conncb_t *)(w->data);
	conn->tx_bytes = recv(conn->sock_local, conn->tx_buf, BUF_SIZE, 0);
	if (conn->tx_bytes <= 0)
	{
		if (conn->tx_bytes < 0)
		{
			ERR("recv");
		}
		ev_io_stop(EV_A_ &conn->w_local_write);
		ev_io_stop(EV_A_ &conn->w_remote_read);
		ev_io_stop(EV_A_ &conn->w_remote_write);
		close(conn->sock_local);
		close(conn->sock_remote);
		mem_delete(conn);
		return;
	}
	ev_io_start(EV_A_ &conn->w_remote_write);
}

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conncb_t *conn = (conncb_t *)(w->data);
	ssize_t n = send(conn->sock_remote, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		ERR("send");
		ev_io_stop(EV_A_ &conn->w_local_read);
		ev_io_stop(EV_A_ &conn->w_local_write);
		ev_io_stop(EV_A_ &conn->w_remote_read);
		close(conn->sock_local);
		close(conn->sock_remote);
		mem_delete(conn);
		return;
	}
	ev_io_start(EV_A_ &conn->w_local_read);
}

static void remote_read_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conncb_t *conn = (conncb_t *)(w->data);
	conn->rx_bytes = recv(conn->sock_remote, conn->rx_buf, BUF_SIZE, 0);
	if (conn->rx_bytes <= 0)
	{
		if (conn->rx_bytes < 0)
		{
			ERR("recv");
		}
		ev_io_stop(EV_A_ &conn->w_local_read);
		ev_io_stop(EV_A_ &conn->w_local_write);
		ev_io_stop(EV_A_ &conn->w_remote_write);
		close(conn->sock_local);
		close(conn->sock_remote);
		mem_delete(conn);
		return;
	}
	ev_io_start(EV_A_ &conn->w_local_write);
}


static void local_write_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conncb_t *conn = (conncb_t *)w->data;
	ssize_t n = send(conn->sock_local, conn->rx_buf, conn->rx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		ERR("send");
		ev_io_stop(EV_A_ &conn->w_local_read);
		ev_io_stop(EV_A_ &conn->w_remote_read);
		ev_io_stop(EV_A_ &conn->w_remote_write);
		close(conn->sock_local);
		close(conn->sock_remote);
		mem_delete(conn);
		return;
	}
	ev_io_start(EV_A_ &conn->w_remote_read);
}

static bool setnonblock(int sock)
{
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1)
	{
		ERR("fcntl");
		return false;
	}
	if (-1 == fcntl(sock, F_SETFL, flags | O_NONBLOCK))
	{
		ERR("fcntl");
		return false;
	}
	return true;
}

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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <ev.h>
#include "log.h"
#include "mem.h"

// 缓冲区大小
#define BUF_SIZE 8192

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

struct
{
	char addr[128];
	socklen_t addrlen;
	int family;
} local, remote;

// 连接控制块
typedef struct
{
	ev_io w_local_read;
	ev_io w_local_write;
	ev_io w_remote_read;
	ev_io w_remote_write;
	ssize_t tx_bytes;
	ssize_t rx_bytes;
	ssize_t rx_offset;
	ssize_t tx_offset;
	int sock_local;
	int sock_remote;
	char rx_buf[BUF_SIZE];
	char tx_buf[BUF_SIZE];
} conn_t;


static void sigint_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void connect_cb(EV_P_ ev_io *w, int revents);
static void local_read_cb(EV_P_ ev_io *w, int revents);
static void local_write_cb(EV_P_ ev_io *w, int revents);
static void remote_read_cb(EV_P_ ev_io *w, int revents);
static void remote_write_cb(EV_P_ ev_io *w, int revents);
static void cleanup(EV_P_ conn_t *conn);
static int setnonblock(int sock);
static int settimeout(int sock);
static int setreuseaddr(int sock);


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

	// 初始化本地监听 socket
	int sock_listen = socket(local.family, SOCK_STREAM, IPPROTO_TCP);
	if (sock_listen < 0)
	{
		ERR("socket");
		return 2;
	}
	setnonblock(sock_listen);
	setreuseaddr(sock_listen);
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
	size_t block_size[1] = { sizeof(conn_t) };
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
	close(sock_listen);

	return 0;
}

static void sigint_cb(EV_P_ ev_signal *w, int revents)
{
	ev_break(EV_A_ EVBREAK_ALL);
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	LOG("local connection established");

	conn_t *conn = (conn_t *)mem_new(sizeof(conn_t));
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
	setnonblock(conn->sock_local);
	settimeout(conn->sock_local);
	conn->sock_remote = socket(remote.family, SOCK_STREAM, IPPROTO_TCP);
	if (conn->sock_remote < 0)
	{
		ERR("socket");
		close(conn->sock_local);
		mem_delete(conn);
		return;
	}
	setnonblock(conn->sock_remote);
	settimeout(conn->sock_remote);
	ev_io_init(&conn->w_remote_write, connect_cb, conn->sock_remote, EV_WRITE);
	conn->w_remote_write.data = (void *)conn;
	ev_io_start(EV_A_ &conn->w_remote_write);
	connect(conn->sock_remote, (struct sockaddr *)remote.addr, remote.addrlen);
}

static void connect_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conn_t *conn = (conn_t *)(w->data);
	int error = 0;
	socklen_t len = sizeof(int);

	getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (error != 0)
	{
		LOG("connect failed");
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
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);

	conn->tx_bytes = recv(conn->sock_local, conn->tx_buf, BUF_SIZE, 0);
	if (conn->tx_bytes <= 0)
	{
		if (conn->tx_bytes < 0)
		{
#ifndef NDEBUG
			ERR("recv");
#endif
			LOG("client reset");
		}
		cleanup(EV_A_ conn);
		return;
	}
	ssize_t n = send(conn->sock_remote, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			conn->tx_offset = 0;
		}
		else
		{
			ERR("send");
			cleanup(EV_A_ conn);
			return;
		}
	}
	else if (n < conn->tx_bytes)
	{
		conn->tx_offset = n;
		conn->tx_bytes -= n;
	}
	else
	{
		return;
	}
	ev_io_start(EV_A_ &conn->w_remote_write);
	ev_io_stop(EV_A_ w);
}

static void local_write_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn->rx_bytes > 0);

	ssize_t n = send(conn->sock_local, conn->rx_buf + conn->rx_offset, conn->rx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			return;
		}
		else
		{
			ERR("send");
			cleanup(EV_A_ conn);
			return;
		}
	}
	else if (n < conn->rx_bytes)
	{
		conn->rx_offset += n;
		conn->rx_bytes -= n;
	}
	else
	{
		ev_io_start(EV_A_ &conn->w_remote_read);
		ev_io_stop(EV_A_ w);
	}
}

static void remote_read_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);

	conn->rx_bytes = recv(conn->sock_remote, conn->rx_buf, BUF_SIZE, 0);
	if (conn->rx_bytes <= 0)
	{
		if (conn->rx_bytes < 0)
		{
#ifndef NDEBUG
			ERR("recv");
#endif
			LOG("remote server reset");
		}
		cleanup(EV_A_ conn);
		return;
	}
	ssize_t n = send(conn->sock_local, conn->rx_buf, conn->rx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			conn->rx_offset = 0;
		}
		else
		{
			ERR("send");
			cleanup(EV_A_ conn);
			return;
		}
	}
	else if (n < conn->rx_bytes)
	{
		conn->rx_offset = n;
		conn->rx_bytes -= n;
	}
	else
	{
		return;
	}
	ev_io_start(EV_A_ &conn->w_local_write);
	ev_io_stop(EV_A_ w);
}

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);
	assert(conn->tx_bytes > 0);

	ssize_t n = send(conn->sock_remote, conn->tx_buf + conn->tx_offset, conn->tx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			return;
		}
		else
		{
			ERR("send");
			cleanup(EV_A_ conn);
			return;
		}
	}
	else if (n < conn->tx_bytes)
	{
		conn->tx_offset += n;
		conn->tx_bytes -= n;
	}
	else
	{
		ev_io_start(EV_A_ &conn->w_local_read);
		ev_io_stop(EV_A_ w);
	}
}

static void cleanup(EV_P_ conn_t *conn)
{
	ev_io_stop(EV_A_ &conn->w_local_read);
	ev_io_stop(EV_A_ &conn->w_local_write);
	ev_io_stop(EV_A_ &conn->w_remote_read);
	ev_io_stop(EV_A_ &conn->w_remote_write);
	close(conn->sock_local);
	close(conn->sock_remote);
	mem_delete(conn);
}

static int setnonblock(int sock)
{
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1)
	{
		return -1;
	}
	if (-1 == fcntl(sock, F_SETFL, flags | O_NONBLOCK))
	{
		return -1;
	}
	return 0;
}

static int settimeout(int sock)
{
	struct timeval timeout = { .tv_sec = 10, .tv_usec = 0};
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)) != 0)
	{
		return -1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) != 0)
	{
		return -1;
	}
	return 0;
}

static int setreuseaddr(int sock)
{
	int reuseaddr = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) != 0)
	{
		return -1;
	}
	return 0;
}


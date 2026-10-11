/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the high-level API for CMU-TCP sockets.
 */

#include "cmu_tcp.h"
#include "backend.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

int cmu_socket(cmu_socket_t *s, const cmu_socket_type_t type,
               const int port, const char *server_ip) {
  if (!s || port < 0 || port > UINT16_MAX ||
      (type != TCP_INITIATOR && type != TCP_LISTENER) ||
      (type == TCP_INITIATOR && (!server_ip || !port))) return EXIT_ERROR;
  memset(s, 0, sizeof(*s));
  s->socket = -1;
  s->type = type;
  s->conn.sin_family = AF_INET;
  s->conn.sin_port = htons(port);
  if (type == TCP_INITIATOR &&
      inet_pton(AF_INET, server_ip, &s->conn.sin_addr) != 1) return EXIT_ERROR;
   
  size_t filled = 0;
  while (filled < sizeof(s->initial_seq)) {
    ssize_t n = getrandom((uint8_t *)&s->initial_seq + filled,
                          sizeof(s->initial_seq) - filled, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return EXIT_ERROR;
    filled += n;
  }
  s->window.last_ack_received = s->initial_seq;
  s->next_seq = s->initial_seq + 1;
  s->socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (s->socket < 0) return EXIT_ERROR;
  struct sockaddr_in local = {0};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = type == TCP_LISTENER ? htons(port) : 0;
  int reuse = 1;
  if (type == TCP_LISTENER)
    setsockopt(s->socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  socklen_t size = sizeof(local);
  if (bind(s->socket, (struct sockaddr *)&local, sizeof(local)) < 0 ||
      getsockname(s->socket, (struct sockaddr *)&local, &size) < 0) goto socket_error;
  s->my_port = ntohs(local.sin_port);
  if (pthread_mutex_init(&s->recv_lock, NULL)) goto socket_error;
  if (pthread_mutex_init(&s->send_lock, NULL)) goto recv_error;
  if (pthread_mutex_init(&s->death_lock, NULL)) goto send_error;
  if (pthread_cond_init(&s->wait_cond, NULL)) goto death_error;
  if (pthread_create(&s->thread_id, NULL, begin_backend, s)) goto cond_error;
  return EXIT_SUCCESS;
cond_error:
  pthread_cond_destroy(&s->wait_cond);
death_error:
  pthread_mutex_destroy(&s->death_lock);
send_error:
  pthread_mutex_destroy(&s->send_lock);
recv_error:
  pthread_mutex_destroy(&s->recv_lock);
socket_error:
  close(s->socket);
  s->socket = -1;
  return EXIT_ERROR;
}

int cmu_close(cmu_socket_t *s) {
  if (!s || s->socket < 0) return EXIT_ERROR;
  pthread_mutex_lock(&s->death_lock);
  s->dying = 1;
  pthread_mutex_unlock(&s->death_lock);
  if (pthread_join(s->thread_id, NULL)) return EXIT_ERROR;
  int failed = s->backend_error;
  free(s->received_buf);
  free(s->sending_buf);
  s->received_buf = s->sending_buf = NULL;
  int result = close(s->socket);
  s->socket = -1;
  pthread_cond_destroy(&s->wait_cond);
  pthread_mutex_destroy(&s->recv_lock);
  pthread_mutex_destroy(&s->send_lock);
  pthread_mutex_destroy(&s->death_lock);
  return failed || result < 0 ? EXIT_ERROR : EXIT_SUCCESS;
}

int cmu_read(cmu_socket_t *s, void *buf, int length, cmu_read_mode_t flags) {
  if (!s || s->socket < 0 || length < 0 || (length && !buf) ||
      (flags != NO_FLAG && flags != NO_WAIT)) return EXIT_ERROR;
  if (!length) return 0;
  pthread_mutex_lock(&s->recv_lock);
  while (flags == NO_FLAG && !s->received_len && !s->backend_error)
    pthread_cond_wait(&s->wait_cond, &s->recv_lock);
  int n = s->received_len < length ? s->received_len : length;
  if (n) {
    memcpy(buf, s->received_buf, n);
    s->received_len -= n;
    if (s->received_len)
      memmove(s->received_buf, s->received_buf + n, s->received_len);
    else {
      free(s->received_buf);
      s->received_buf = NULL;
    }
  } else if (s->backend_error) {
    n = EXIT_ERROR;
  }
  pthread_mutex_unlock(&s->recv_lock);
  return n;
}

int cmu_write(cmu_socket_t *s, const void *buf, int length) {
  if (!s || s->socket < 0 || length < 0 || (length && !buf)) return EXIT_ERROR;
  pthread_mutex_lock(&s->death_lock);
  int dying = s->dying;
  pthread_mutex_unlock(&s->death_lock);
  pthread_mutex_lock(&s->recv_lock);
  int failed = s->backend_error;
  pthread_mutex_unlock(&s->recv_lock);
  if (dying || failed) return EXIT_ERROR;
  if (!length) return EXIT_SUCCESS;
  pthread_mutex_lock(&s->send_lock);
  if (length > INT_MAX - s->sending_len) {
    pthread_mutex_unlock(&s->send_lock);
    return EXIT_ERROR;
  }
  uint8_t *p = realloc(s->sending_buf, s->sending_len + length);
  if (!p) {
    pthread_mutex_unlock(&s->send_lock);
    return EXIT_ERROR;
  }
  s->sending_buf = p;
  memcpy(p + s->sending_len, buf, length);
  s->sending_len += length;
  pthread_mutex_unlock(&s->send_lock);
  return EXIT_SUCCESS;
}

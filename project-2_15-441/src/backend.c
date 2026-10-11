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
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"
#include "cmu_tcp.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED };
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void fail_backend(cmu_socket_t *s) {
  pthread_mutex_lock(&s->recv_lock);
  s->backend_error = 1;
  pthread_cond_broadcast(&s->wait_cond);
  pthread_mutex_unlock(&s->recv_lock);
}


static int transmit(cmu_socket_t *s, uint8_t flags, uint32_t seq,
                    uint32_t ack, const uint8_t *data, uint16_t len) {
  uint8_t packet[MAX_LEN];
  cmu_tcp_header_t *h = (cmu_tcp_header_t *)packet;
  memset(h, 0, sizeof(*h));
  h->identifier = htonl(IDENTIFIER);
  set_src(h, s->my_port);
  set_dst(h, ntohs(s->conn.sin_port));
  set_seq(h, seq);
  set_ack(h, ack);
  set_hlen(h, sizeof(*h));
  set_plen(h, sizeof(*h) + len);
  set_flags(h, flags);
  set_advertised_window(h, MIN((uint32_t)CP1_WINDOW_SIZE, UINT16_MAX));
  if (len) memcpy(packet + sizeof(*h), data, len);
  ssize_t n;
  do {
    n = sendto(s->socket, packet, sizeof(*h) + len, 0,
               (struct sockaddr *)&s->conn, sizeof(s->conn));
  } while (n < 0 && errno == EINTR);
   
  return n >= 0 || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS;
}

static int handshake_packet(cmu_socket_t *s) {
  uint8_t flags = SYN_FLAG_MASK;
  uint32_t ack = 0;
  if (s->connection_state == SYN_RECEIVED) {
    flags |= ACK_FLAG_MASK;
    ack = s->window.next_seq_expected;
  }
  s->retransmit_at = now_ms() + DEFAULT_TIMEOUT;
  return transmit(s, flags, s->initial_seq, ack, NULL, 0);
}

static int send_ack(cmu_socket_t *s) {
  return transmit(s, ACK_FLAG_MASK, s->next_seq,
                  s->window.next_seq_expected, NULL, 0);
}

static int receive_packet(cmu_socket_t *s) {
  uint8_t packet[MAX_LEN + 1];
  struct sockaddr_in peer;
  socklen_t peer_len = sizeof(peer);
  ssize_t n = recvfrom(s->socket, packet, sizeof(packet), MSG_DONTWAIT,
                       (struct sockaddr *)&peer, &peer_len);
  if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
  if (n < (ssize_t)sizeof(cmu_tcp_header_t) || n > MAX_LEN) return 1;
  cmu_tcp_header_t *h = (cmu_tcp_header_t *)packet;
  uint16_t hlen = get_hlen(h), plen = get_plen(h);
  if (ntohl(h->identifier) != IDENTIFIER || plen != n || hlen > plen ||
      hlen < sizeof(*h) || hlen != sizeof(*h) + get_extension_length(h) ||
      get_src(h) != ntohs(peer.sin_port) || get_dst(h) != s->my_port) return 1;
  uint16_t len = plen - hlen;
  uint8_t flags = get_flags(h);
  uint32_t seq = get_seq(h), ack = get_ack(h);
  if (s->connection_state != LISTEN &&
      (peer.sin_addr.s_addr != s->conn.sin_addr.s_addr ||
       peer.sin_port != s->conn.sin_port)) return 1;

  if (s->connection_state == LISTEN) {
    if (flags != SYN_FLAG_MASK || len != 0) return 1;
    s->conn = peer;
    s->peer_initial_seq = seq;
    s->window.next_seq_expected = seq + 1;
    s->connection_state = SYN_RECEIVED;
    return handshake_packet(s);
  }
  if (s->connection_state == SYN_SENT) {
    if (flags != (SYN_FLAG_MASK | ACK_FLAG_MASK) || len ||
        ack != s->initial_seq + 1) return 1;
    s->peer_initial_seq = seq;

    s->window.next_seq_expected = seq + 1;
    s->window.last_ack_received = ack;
    s->next_seq = ack;
    s->connection_state = ESTABLISHED;
    s->retransmit_at = 0;
    return send_ack(s);
  }
  if (s->connection_state == SYN_RECEIVED) {
    if (flags == SYN_FLAG_MASK && !len && seq == s->peer_initial_seq)
      return handshake_packet(s);
    if (flags != ACK_FLAG_MASK || len || ack != s->initial_seq + 1 ||
        seq != s->window.next_seq_expected) return 1;
    s->window.last_ack_received = ack;
    s->next_seq = ack;
    s->connection_state = ESTABLISHED;
    s->retransmit_at = 0;
    return 1;
  }

  if (flags == (SYN_FLAG_MASK | ACK_FLAG_MASK) && !len &&
      s->type == TCP_INITIATOR && seq == s->peer_initial_seq &&
      ack == s->initial_seq + 1)
    return transmit(s, ACK_FLAG_MASK, s->initial_seq + 1,
                    s->peer_initial_seq + 1, NULL, 0);
  if (flags != 0 && flags != ACK_FLAG_MASK) return 1;
  s->last_receive_at = now_ms();
  if (flags & ACK_FLAG_MASK) {

    pthread_mutex_lock(&s->send_lock);
    uint32_t count = ack - s->window.last_ack_received;
    if (count > 0 && count <= (uint32_t)s->sent_len) {
      memmove(s->sending_buf, s->sending_buf + count, s->sending_len - count);
      s->sending_len -= count;
      s->sent_len -= count;
      s->window.last_ack_received = ack;
      s->retransmit_at = s->sent_len ? now_ms() + DEFAULT_TIMEOUT : 0;
      if (!s->sending_len) {
        free(s->sending_buf);
        s->sending_buf = NULL;
      }
    }
    pthread_mutex_unlock(&s->send_lock);
  }
  if (len) {
    pthread_mutex_lock(&s->recv_lock);
    if (seq == s->window.next_seq_expected &&
        s->received_len <= INT_MAX - len) {
      uint8_t *new_buf = realloc(s->received_buf, s->received_len + len);
      if (!new_buf) {
        pthread_mutex_unlock(&s->recv_lock);
        return 0;
      }
      s->received_buf = new_buf;
      memcpy(new_buf + s->received_len, packet + hlen, len);
      s->received_len += len;
      s->window.next_seq_expected += len;
      pthread_cond_broadcast(&s->wait_cond);
    }
    pthread_mutex_unlock(&s->recv_lock);

    return send_ack(s);
  }
  return 1;
}

static int send_window(cmu_socket_t *s) {
  int ok = 1;
  int64_t now = now_ms();
  pthread_mutex_lock(&s->send_lock);
  if (s->sent_len && now >= s->retransmit_at) {
     
    for (int offset = 0; offset < s->sent_len && ok;) {
      uint16_t len = MIN((uint32_t)(s->sent_len - offset), (uint32_t)MSS);
      ok = transmit(s, 0, s->window.last_ack_received + offset,
                    s->window.next_seq_expected, s->sending_buf + offset, len);
      
                    offset += len;
    }
    s->retransmit_at = now + DEFAULT_TIMEOUT;
  }
  while (ok && s->sent_len < s->sending_len &&
         (uint32_t)s->sent_len < (uint32_t)CP1_WINDOW_SIZE) {
    uint32_t space = (uint32_t)CP1_WINDOW_SIZE - s->sent_len;
    uint16_t len = MIN((uint32_t)MSS,
                      MIN(space, (uint32_t)(s->sending_len - s->sent_len)));
    ok = transmit(s, 0, s->next_seq, s->window.next_seq_expected,
                  s->sending_buf + s->sent_len, len);
    if (!ok) break;
    if (!s->sent_len) s->retransmit_at = now + DEFAULT_TIMEOUT;
    
    s->sent_len += len;
    s->next_seq += len;
  }
  pthread_mutex_unlock(&s->send_lock);
  return ok;
}

void *begin_backend(void *in) {
  cmu_socket_t *s = in;
  int64_t close_at = 0;
  s->connection_state = s->type == TCP_INITIATOR ? SYN_SENT : LISTEN;
  if (s->connection_state == SYN_SENT && !handshake_packet(s)) goto failure;
  for (;;) {
    pthread_mutex_lock(&s->death_lock);
    int dying = s->dying;

    pthread_mutex_unlock(&s->death_lock);
    pthread_mutex_lock(&s->send_lock);
    
    int pending = s->sending_len;
    
    pthread_mutex_unlock(&s->send_lock);
    if (dying && !pending) {
      if (s->connection_state != ESTABLISHED) break;

      if (!close_at) close_at = now_ms() + 2 * DEFAULT_TIMEOUT;
      if (now_ms() >= close_at &&
          now_ms() - s->last_receive_at >= 2 * DEFAULT_TIMEOUT) break;
    } else {
      close_at = 0;
    }
    if (s->connection_state == ESTABLISHED) {
      if (!send_window(s)) goto failure;
    } else if (s->connection_state != LISTEN && now_ms() >= s->retransmit_at) {
      if (!handshake_packet(s)) goto failure;
    }
    struct pollfd fd = {s->socket, POLLIN, 0};
    int result = poll(&fd, 1, 10);

    if (result < 0 && errno != EINTR) goto failure;
    if (result > 0) {
      if (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) goto failure;
      if ((fd.revents & POLLIN) && !receive_packet(s)) goto failure;
    }
  }
  return NULL;
failure:
  fail_backend(s);
  return NULL;
}

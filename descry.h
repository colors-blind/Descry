/*
 *  Building Open Source Network Security Tools
 *  descry.h - Network Intrusion Detection Technique example code
 *
 *  Copyright (c) 2002 Dominique Brezinkski <db@infonexus.com>
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef DESCRY_H
#define DESCRY_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#define MAX_STRING          0x100
#define CON_REMOVED_TAG     0xDEADBEEF
#define CLEANUP_INTERVAL    1000
#define EXPIRE_TIME         11800
#define MAX_PACKET          1500

#define FILTER  "((tcp[13] & 0x12) == 0x12) || " \
                "((tcp[13] & 0x11) == 0x11) || " \
                "((tcp[13] & 0x14) == 0x14) || " \
                "((tcp[13] & 0x04) == 0x04)"

#define KEY_BYTES       12
#define MIN_KEY_BIT     0
#define MAX_KEY_BIT     (KEY_BYTES * 8 - 1)

/* Ethernet header length */
#define ETHER_HDR_LEN   14
/* Minimum IP header length */
#define MIN_IP_HDR_LEN  20
/* Minimum TCP header length */
#define MIN_TCP_HDR_LEN 20

/* TCP flags (matching pcap filter usage) */
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_ACK    0x10

#define PTIMERSUB(tvp, uvp, vvp)                            \
do {                                                        \
    (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
    (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
    if ((vvp)->tv_usec < 0) {                               \
        (vvp)->tv_sec--;                                    \
        (vvp)->tv_usec += 1000000;                          \
    }                                                       \
} while (0)

#define SET_STATE(c, dip, dp, sip, sp, s)   \
do {                                        \
    (c)->dst_addr.s_addr = (dip);           \
    (c)->dst_port = (dp);                   \
    (c)->src_addr.s_addr = (sip);           \
    (c)->src_port = (sp);                   \
    (c)->seq = (s);                         \
} while (0)

struct tcp_connection {
    struct in_addr src_addr;
    struct in_addr dst_addr;
    struct timeval ts;
    uint32_t seq;
    uint16_t src_port;
    uint16_t dst_port;
};

struct pt_node {
    int bit;
    struct pt_node *l;
    struct pt_node *r;
    struct tcp_connection *con;
    bool removed;
};

struct pt_context {
    struct pt_node *head;
    uint32_t n;
};

struct descry_pack {
    pcap_t *p;
    uint8_t flags;
#define ALL_HOSTS   0x01
#define DO_SYSLOG   0x02
    int offset;
    struct pt_context *pt;
};

int  descry_init(struct descry_pack **gp, const char *device,
                 const char *capture_file, uint8_t flags);
void descry_destroy(struct descry_pack *gp);
void descry(uint8_t *u, struct pcap_pkthdr *phdr, const uint8_t *packet);
void check_state(struct descry_pack *gp, struct tcp_connection *con1,
                 struct tcp_connection *con2);
int  pt_init(struct pt_context **p);
struct pt_node *pt_new(int bit, struct pt_node *l, struct pt_node *r,
                       struct tcp_connection *con);
int  pt_insert(struct pt_context *pt, struct tcp_connection *c);
void pt_expire(struct descry_pack *gp, struct timeval *ts);
int  pt_find(struct pt_context *pt, struct tcp_connection *c,
             struct tcp_connection **rc);
void pt_delete(struct pt_context *pt, struct tcp_connection *c);
void pt_make_key(uint8_t *key, const struct tcp_connection *c);
void pt_walk_r(struct descry_pack *gp, struct pt_node *cur,
               struct pt_node *pre, struct timeval *ts);
int  pt_remove_r(struct pt_context *pt, struct pt_node *n, uint8_t *key,
                 struct pt_node *prev);
int  pt_search_r(struct pt_node *n, uint8_t *key, struct pt_node **rc);
int  diff_bit(const uint8_t *key1, const uint8_t *key2, int *b);
int  get_bit(const uint8_t *key, struct pt_node *n);
const char *get_time(void);
void usage(const char *name);

#endif /* DESCRY_H */

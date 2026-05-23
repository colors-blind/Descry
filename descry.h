/*
 *  $Id: descry.h,v 1.1.1.1 2002/05/28 17:06:45 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  descry.c - Network Intrusion Detection Technique example code
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
 *
 */

#include <syslog.h>
#include <libnet.h>
#include <pcap.h>

/* misc defines */
#define MAX_STRING      0x100       /* default string length */
#define CON_REMOVED     0xFFFFFFFF  /* tag a node for removal */
#define CLEANUP_INTERVAL 1000       /* how often the cleaner runs */
#define EXPIRE_TIME     11800       /* seconds that a connection should
                                     * should linger in SYN-ACK state
                                     * before it gets expired
                                     */
#define MAX_PACKET      1500        /* max packet size */

/* filter to catch SYN-ACK, FIN-ACK, and RST segments */
#define FILTER              "((tcp[13] & 0x12) == 0x12) || \
                             ((tcp[13] & 0x11) == 0x11) || \
                             ((tcp[13] & 0x14) == 0x14) || \
                             ((tcp[13] & 0x04) == 0x04)"


/* patricia key symbolic constants */
#define KEY_BYTES       12
#define MIN_KEY_BIT     0
#define MAX_KEY_BIT     (KEY_BYTES * 8 - 1)

/*
 *  Simple way to subtract timeval based timers.  Not every OS has this,
 *  so we'll just define it here.
 */
#define PTIMERSUB(tvp, uvp, vvp)                            \
do                                                          \
{                                                           \
    (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
    (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
    if ((vvp)->tv_usec < 0)                                 \
    {                                                       \
        (vvp)->tv_sec--;                                    \
        (vvp)->tv_usec += 1000000;                          \
    }                                                       \
}                                                           \
while (0)                                                   \

/* code cleanup to set connection state */
#define SET_STATE(c, dip, dp, sip, sp, s)                   \
{                                                           \
    c->dst_addr.s_addr = dip;                               \
    c->dst_port = dp;                                       \
    c->src_addr.s_addr = sip;                               \
    c->src_port = sp;                                       \
    c->seq = s;                                             \
}                                                           \

/* TCP connection info */
struct tcp_connection
{
    struct in_addr src_addr;        /* source address */
    struct in_addr dst_addr;        /* destination address */
    struct timeval ts;              /* time value */
    u_long seq;                     /* sequence number */
    u_short src_port;               /* source port */
    u_short dst_port;               /* destination port */
};

/* decision node within the patricia trie */
struct pt_node
{
    int bit;                        /* decision bit */
    struct pt_node *l;              /* left node */
    struct pt_node *r;              /* right node */
    struct tcp_connection *con;     /* connection info */
};

/* patricia trie context */
struct pt_context
{
    struct pt_node *head;           /* head of the trie */
    u_long n;                       /* number of existing nodes */
};

/* main descry control context */
struct descry_pack
{
    pcap_t *p;                      /* libpcap context */
    u_char flags;                   /* control flags */
#define ALL_HOSTS   0x01            /* monitor all hosts on segment */
#define DO_SYSLOG   0x02            /* log to syslog */
    int offset;                     /* offset to IP header */
    struct pt_context *pt;          /* patricia trie context */
};

int  descry_init(struct descry_pack **, char *, char *, u_char);
void descry_destroy(struct descry_pack *);
void descry(u_char *, struct pcap_pkthdr *, u_char *);
void check_state(struct descry_pack *, struct tcp_connection *,
        struct tcp_connection *);
int  pt_init(struct pt_context **);
struct pt_node *pt_new(int bit, struct pt_node *, struct pt_node *,
        struct tcp_connection *);
int  pt_insert(struct pt_context *, struct tcp_connection *);
void pt_expire(struct descry_pack *, struct timeval*);
int  pt_find(struct pt_context *, struct tcp_connection *,
        struct tcp_connection **);
void pt_delete(struct pt_context *, struct tcp_connection *);
void pt_make_key(u_char *, struct tcp_connection *);
void pt_walk_r(struct descry_pack *, struct pt_node *, struct pt_node *,
        struct timeval*);
int  pt_remove_r(struct pt_context *, struct pt_node *, u_char *, 
        struct pt_node *);
int  pt_search_r(struct pt_node *, u_char *, struct pt_node **);
int diff_bit(u_char *, u_char *, int *);
int get_bit(u_char *, struct pt_node *);
char * get_time();
void usage(char*);

/* EOF */


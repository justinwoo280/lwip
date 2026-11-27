/* A software fallback during retransmission must get past an ACKed prefix. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/inet_chksum.h>
#include <lwip/priv/tcp_priv.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }
enum { MSS = 1200, LENGTH = 4 * MSS };
static u8_t data[LENGTH];
static u32_t first_seq, acked_seq;
static unsigned new_bytes, duplicates, refused, sent_acked, fins;
static int fallback;
static struct tcp_pcb *active;

static err_t sent(void *arg, struct tcp_pcb *pcb, u16_t n) {
    (void)arg; (void)pcb; sent_acked += n; return ERR_OK;
}
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *dest) {
    struct tcp_hdr h;
    u8_t payload[LENGTH];
    const struct ip_hdr *ip = p->payload;
    (void)n; (void)dest;
    unsigned iplen = IPH_HL_BYTES(ip);
    assert(IPH_PROTO(ip) == 6 && IPH_OFFSET(ip) == 0);
    assert(pbuf_copy_partial(p, &h, sizeof(h), iplen) == sizeof(h));
    unsigned hlen = iplen + TCPH_HDRLEN_BYTES(&h), len = p->tot_len - hlen;
    if (!len) return ERR_OK;
    u32_t seq = lwip_ntohl(h.seqno);
    assert(seq - first_seq + len <= LENGTH);
    assert(pbuf_copy_partial(p, payload, len, hlen) == len);
    assert(!memcmp(payload, data + (seq - first_seq), len));
    if (fallback) {
        if (len > MSS) { refused++; return ERR_MEM; }
        assert(TCP_SEQ_LEQ(seq + len, active->lastack + active->cwnd));
        if (TCPH_FLAGS(&h) & TCP_FIN) {
            assert(seq + len == first_seq + LENGTH); fins++;
        }
        if (TCP_SEQ_LEQ(seq + len, acked_seq)) duplicates++;
        else new_bytes += len;
    }
    return ERR_OK;
}
static err_t init_if(struct netif *n) {
    n->mtu = 9000; n->output = output; return ERR_OK;
}
static void ack(struct netif *n, u32_t seq) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, IP_HLEN + TCP_HLEN, PBUF_RAM); assert(p);
    memset(p->payload, 0, p->len);
    struct ip_hdr *ip = p->payload;
    struct tcp_hdr *tcp = (struct tcp_hdr *)((u8_t *)p->payload + IP_HLEN);
    IPH_VHL_SET(ip, 4, 5); IPH_LEN_SET(ip, lwip_htons(p->len));
    IPH_TTL_SET(ip, 64); IPH_PROTO_SET(ip, 6);
    ip->src.addr = ip_2_ip4(&active->remote_ip)->addr;
    ip->dest.addr = ip_2_ip4(&active->local_ip)->addr;
    IPH_CHKSUM_SET(ip, inet_chksum(ip, IP_HLEN));
    tcp->src = lwip_htons(active->remote_port); tcp->dest = lwip_htons(active->local_port);
    tcp->seqno = lwip_htonl(active->rcv_nxt); tcp->ackno = lwip_htonl(seq);
    tcp->wnd = lwip_htons(32000); TCPH_HDRLEN_FLAGS_SET(tcp, 5, TCP_ACK);
    assert(!pbuf_remove_header(p, IP_HLEN));
    tcp->chksum = inet_chksum_pseudo(p, 6, TCP_HLEN,
        ip_2_ip4(&active->remote_ip), ip_2_ip4(&active->local_ip));
    assert(!pbuf_add_header(p, IP_HLEN));
    assert(ip_input(p, n) == ERR_OK);
}
static int run(u32_t start, int backoff, int finish) {
    struct netif n = {0};
    ip4_addr_t local, mask, gw;
    lwip_init();
    IP4_ADDR(&local, 192, 0, 2, 1); IP4_ADDR(&mask, 255, 255, 255, 0); ip4_addr_set_zero(&gw);
    assert(netif_add(&n, &local, &mask, &gw, NULL, init_if, ip_input));
    netif_set_up(&n); netif_set_link_up(&n);
    active = tcp_new_ip_type(IPADDR_TYPE_V4); assert(active);
    assert(ipaddr_aton("192.0.2.1", &active->local_ip) && ipaddr_aton("192.0.2.2", &active->remote_ip));
    active->local_port = 1234; active->remote_port = 40000;
    tcp_bind_netif(active, &n); active->state = ESTABLISHED; TCP_REG_ACTIVE(active);
    first_seq = start; acked_seq = start + 3 * MSS;
    active->lastack = active->snd_lbb = active->snd_nxt = start;
    active->rcv_nxt = 9000;
    active->cwnd = active->snd_wnd = active->snd_wnd_max = 32000;
    active->mss = active->gso_mss = MSS; active->gso_max_size = LENGTH;
    tcp_nagle_disable(active); tcp_sent(active, sent);
    new_bytes = duplicates = refused = sent_acked = fins = 0; fallback = 0;
    assert(tcp_write(active, data, sizeof(data), TCP_WRITE_FLAG_COPY) == ERR_OK);
    if (finish) { assert(tcp_shutdown(active, 0, 1) == ERR_OK); }
    else { assert(tcp_output(active) == ERR_OK); }
    ack(&n, acked_seq);
    assert(active->lastack == acked_seq && active->unacked && active->unacked->len == LENGTH);
    assert(tcp_rexmit_rto_prepare(active) == ERR_OK);
    active->cwnd = MSS;
    if (backoff) active->gso_off_timer = 8;
    fallback = 1;
    assert(tcp_output(active) == ERR_OK);
    int failed = new_bytes != MSS || fins != (unsigned)finish;
    printf("GSO partial-ACK retransmit: wrap=%d backoff=%d FIN=%d refused=%u duplicates=%u new_bytes=%u\n",
           start > 0xffff0000u, backoff, finish, refused, duplicates, new_bytes);
    if (!failed) {
        ack(&n, start + LENGTH + finish);
        assert(!active->unsent && !active->unacked && !active->snd_queuelen);
        assert(active->snd_buf == TCP_SND_BUF && sent_acked == LENGTH);
    }
    tcp_abandon(active, 0); netif_remove(&n); lwip_fini();
    return failed;
}
int main(void) {
    for (unsigned i = 0; i < sizeof(data); i++) data[i] = (u8_t)(i * 19 + 3);
    int failed = 0;
    for (int backoff = 0; backoff < 2; backoff++) for (int finish = 0; finish < 2; finish++) {
        failed += run(1000, backoff, finish); failed += run(0xffffff00u, backoff, finish);
    }
    return failed != 0;
}

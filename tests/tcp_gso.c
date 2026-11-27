/* Verify the output contract for devices that dispatch on pbuf.gso_size. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/priv/tcp_priv.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }

enum { MSS = 1200, FIRST_SEQ = 1000 };
static u8_t data[3 * MSS + 333], received[sizeof(data)];
static unsigned used, tagged, plain;
static int refuse;

static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *dest) {
    const struct ip_hdr *ip = p->payload;
    struct tcp_hdr tcp;
    (void)dest;
    assert(IPH_PROTO(ip) == IP_PROTO_TCP && IPH_OFFSET(ip) == 0);
    unsigned hdr = IPH_HL_BYTES(ip);
    assert(pbuf_copy_partial(p, &tcp, sizeof(tcp), hdr) == sizeof(tcp));
    hdr += TCPH_HDRLEN_BYTES(&tcp);
    if (p->gso_size) {
        assert(p->gso_size == MSS);
        tagged++;
        if (refuse) return ERR_MEM;
    } else {
        assert(p->tot_len <= n->mtu && p->tot_len - hdr <= MSS);
        plain++;
    }
    unsigned len = p->tot_len - hdr;
    assert(lwip_ntohl(tcp.seqno) == FIRST_SEQ + used && used + len <= sizeof(data));
    assert(pbuf_copy_partial(p, received + used, len, hdr) == len);
    used += len;
    return ERR_OK;
}

static err_t init_if(struct netif *n) {
    n->output = output; n->mtu = 1500;
    return ERR_OK;
}

static int run(struct netif *n, unsigned len, int refuse_gso) {
    /* Seed the post-handshake state; exercise the real write/split/output path. */
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    assert(pcb);
    assert(ipaddr_aton("192.0.2.1", &pcb->local_ip) && ipaddr_aton("192.0.2.2", &pcb->remote_ip));
    pcb->local_port = 1234; pcb->remote_port = 40000;
    tcp_bind_netif(pcb, n);
    pcb->state = ESTABLISHED;
    TCP_REG_ACTIVE(pcb);
    pcb->lastack = pcb->snd_lbb = pcb->snd_nxt = FIRST_SEQ;
    pcb->cwnd = pcb->snd_wnd_max = pcb->snd_wnd = 32000;
    pcb->mss = pcb->gso_mss = MSS;
    pcb->gso_max_size = 4 * MSS;
    tcp_nagle_disable(pcb);
    used = tagged = plain = 0;
    refuse = refuse_gso;
    assert(tcp_write(pcb, data, len, TCP_WRITE_FLAG_COPY) == ERR_OK);
    err_t err = tcp_output(pcb);
    unsigned want_tagged = len > MSS;
    unsigned want_plain = (len <= MSS || refuse) ? (len + MSS - 1) / MSS : 0;
    int ok = err == ERR_OK && used == len && !memcmp(data, received, len) &&
             tagged == want_tagged && plain == want_plain && pcb->mss == MSS;
    printf("TCP GSO: len=%u refuse=%d tagged=%u plain=%u bytes=%u %s\n",
           len, refuse, tagged, plain, used, ok ? "PASS" : "FAIL");
    tcp_abandon(pcb, 0);
    return !ok;
}

int main(void) {
    struct netif n = {0};
    lwip_init();
    assert(netif_add_noaddr(&n, NULL, init_if, ip_input));
    for (unsigned i = 0; i < sizeof(data); i++) data[i] = (u8_t)(i * 29 + 1);
    int failed = run(&n, sizeof(data), 0);
    failed += run(&n, sizeof(data), 1);
    failed += run(&n, MSS, 1);
    netif_remove(&n);
    lwip_fini();
    return failed != 0;
}

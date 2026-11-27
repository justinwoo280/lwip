/* Send ordinary chained UDP payloads through a synchronous in-memory netif. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/udp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }

static u8_t body[4096], wire[UDP_HLEN + sizeof(body)];
static unsigned body_len, calls, seen, bad_flags, reject_at;
static int ipv6;

static err_t capture(struct netif *n, struct pbuf *p, unsigned header,
                     unsigned offset, int more) {
    unsigned len = p->tot_len - header;
    assert(p->tot_len > header && p->tot_len <= n->mtu);
    assert(offset == seen && offset + len <= sizeof(wire));
    assert(pbuf_copy_partial(p, wire + offset, len, header) == len);
    seen += len;
    if (more != (seen < body_len + UDP_HLEN)) bad_flags++;
    return ++calls == reject_at ? ERR_IF : ERR_OK;
}

static err_t output4(struct netif *n, struct pbuf *p, const ip4_addr_t *dest) {
    const struct ip_hdr *h = p->payload;
    (void)dest;
    assert(IPH_PROTO(h) == IP_PROTO_UDP && IPH_HL_BYTES(h) == IP_HLEN);
    return capture(n, p, IP_HLEN, IPH_OFFSET_BYTES(h), !!(lwip_ntohs(IPH_OFFSET(h)) & IP_MF));
}

static err_t output6(struct netif *n, struct pbuf *p, const ip6_addr_t *dest) {
    const struct ip6_hdr *h = p->payload;
    struct ip6_frag_hdr f;
    (void)dest;
    assert(IP6H_NEXTH(h) == IP6_NEXTH_FRAGMENT);
    assert(pbuf_copy_partial(p, &f, sizeof(f), IP6_HLEN) == sizeof(f));
    assert(f._nexth == IP6_NEXTH_UDP);
    unsigned flags = lwip_ntohs(f._fragment_offset);
    return capture(n, p, IP6_HLEN + IP6_FRAG_HLEN, flags & IP6_FRAG_OFFSET_MASK,
                   !!(flags & IP6_FRAG_MORE_FLAG));
}

static err_t init_if(struct netif *n) {
    n->mtu = ipv6 ? 1500 : 1280;
    n->output = output4;
    n->output_ip6 = output6;
    return ERR_OK;
}

static int run(int v6, unsigned reject) {
    struct netif n = {0};
    ip_addr_t src, dest;
    ipv6 = v6;
    reject_at = reject;
    calls = seen = bad_flags = 0;
    /* The last fragment fits the MTU, but isn't a multiple of eight. */
    body_len = reject ? sizeof(body) : (v6 ? 1448 + 1450 : 1256 + 1258) - UDP_HLEN;
    for (unsigned i = 0; i < body_len; i++) body[i] = (u8_t)(i * 17 + 13);

    assert(netif_add_noaddr(&n, NULL, init_if, ip_input));
    assert(ipaddr_aton(v6 ? "fd00::1" : "192.0.2.1", &src));
    assert(ipaddr_aton(v6 ? "fd00::2" : "192.0.2.2", &dest));
    struct udp_pcb *pcb = udp_new_ip_type(IP_GET_TYPE(&src));
    assert(pcb && udp_bind(pcb, &src, 40000) == ERR_OK);

    /* UDP adds a separate header, so both reference buffers belong to us. */
    const unsigned cut = 997;
    struct pbuf *p = pbuf_alloc_reference(body, cut, PBUF_REF);
    struct pbuf *tail = pbuf_alloc_reference(body + cut, body_len - cut, PBUF_REF);
    assert(p && tail);
    pbuf_cat(p, tail);
    err_t err = udp_sendto_if_src(pcb, p, &dest, 1234, &n, &src);
    int intact = p->ref == 1 && p->payload == body && p->len == cut && p->tot_len == body_len &&
                 p->next == tail && tail->ref == 1 && tail->payload == body + cut &&
                 tail->len == body_len - cut && tail->tot_len == tail->len;
    int ok = intact && !bad_flags && calls == (reject ? reject : 2) &&
             (reject ? err == ERR_IF : err == ERR_OK && seen == body_len + UDP_HLEN &&
              !memcmp(wire + UDP_HLEN, body, body_len));
    printf("IPv%d fragment output: reject=%u calls=%u err=%d intact=%d bad_flags=%u %s\n",
           v6 ? 6 : 4, reject, calls, (int)err, intact, bad_flags, ok ? "PASS" : "FAIL");
    pbuf_free(p);
    udp_remove(pcb);
    netif_remove(&n);
    return !ok;
}

int main(void) {
    int failed = 0;
    lwip_init();
    for (int v6 = 0; v6 <= 1; v6++) {
        for (unsigned reject = 0; reject <= 2; reject++) failed += run(v6, reject);
    }
    lwip_fini();
    return failed != 0;
}

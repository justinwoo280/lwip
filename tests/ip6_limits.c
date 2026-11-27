/* IPv6 permits a payload near 64 KiB; lwIP's pbuf must also fit the IP header. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip6_frag.h>
#include <lwip/inet_chksum.h>
#include <lwip/udp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }
static struct netif iface;
static ip6_addr_t source, destination;
static u8_t datagram[65535], received[65535];
static unsigned messages, expected;

static err_t output(struct netif *n, struct pbuf *p, const ip6_addr_t *a) {
    (void)n; (void)p; (void)a; return ERR_OK;
}
static err_t init_if(struct netif *n) { n->mtu = 1500; n->output_ip6 = output; return ERR_OK; }
static void recv_udp(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *a, u16_t port) {
    (void)arg; (void)pcb; (void)a;
    assert(port == 40000 && p->tot_len == expected - 8);
    assert(pbuf_copy_partial(p, received, p->tot_len, 0) == p->tot_len);
    assert(!memcmp(received, datagram + 8, p->tot_len));
    messages++; pbuf_free(p);
}
static void be16(u8_t *p, unsigned n) { p[0] = (u8_t)(n >> 8); p[1] = (u8_t)n; }
static void input(unsigned offset, unsigned len, unsigned extra, int more) {
    unsigned hlen = 48 + extra;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)(hlen + len), PBUF_RAM); assert(p);
    u8_t *bytes = p->payload; memset(bytes, 0, hlen);
    bytes[0] = 0x60; bytes[6] = extra ? 0 : 44; bytes[7] = 64;
    be16(bytes + 4, extra + 8 + len);
    memcpy(bytes + 8, source.addr, 16); memcpy(bytes + 24, destination.addr, 16);
    if (extra) bytes[40] = 44; /* Eight-byte Hop-by-Hop header with Pad1 options. */
    bytes[40 + extra] = 17; be16(bytes + 42 + extra, offset | (more ? 1 : 0));
    bytes[47 + extra] = 42;
    memcpy(bytes + hlen, datagram + offset, len);
    assert(ip_input(p, &iface) == ERR_OK);
}
static int run(unsigned total, unsigned extra, unsigned last_extra, int reversed) {
    expected = total; messages = 0;
    memset(datagram, 0, total);
    be16(datagram, 40000); be16(datagram + 2, 1234); be16(datagram + 4, total);
    for (unsigned i = 8; i < total; i++) datagram[i] = (u8_t)(i * 37 + 11);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)total, PBUF_RAM); assert(p);
    assert(pbuf_take(p, datagram, total) == ERR_OK);
    u16_t sum = ip6_chksum_pseudo(p, 17, (u16_t)total, &source, &destination);
    if (!sum) sum = 0xffff;
    memcpy(datagram + 6, &sum, 2); pbuf_free(p);
    printf("IPv6 reassembly length=%u extra=%u/%u reversed=%d\n", total + 40 + extra, extra, last_extra, reversed);
    if (reversed) input(40000, total - 40000, last_extra, 0);
    input(0, 40000, extra, 1);
    if (!reversed) input(40000, total - 40000, last_extra, 0);
    int failed = messages != (total + 40 + extra <= 65535);
    for (unsigned i = 0; i <= IPV6_REASS_MAXAGE; i++) ip6_reass_tmr();
    return failed;
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    lwip_init();
    assert(netif_add_noaddr(&iface, NULL, init_if, ip_input));
    assert(ip6addr_aton("fd00::10", &source) && ip6addr_aton("fd00::20", &destination));
    s8_t index; assert(netif_add_ip6_address(&iface, &destination, &index) == ERR_OK);
    netif_ip6_addr_set_state(&iface, index, IP6_ADDR_PREFERRED);
    netif_set_up(&iface); netif_set_link_up(&iface); netif_set_default(&iface);
    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_V6); assert(pcb);
    assert(udp_bind(pcb, IP6_ADDR_ANY, 1234) == ERR_OK); udp_recv(pcb, recv_udp, NULL);
    int failed = 0;
    for (unsigned extra = 0; extra <= 8; extra += 8) for (int reversed = 0; reversed < 2; reversed++) {
        failed += run(65535 - 40 - extra, extra, extra, reversed);
        failed += run(65536 - 40 - extra, extra, extra, reversed);
        failed += run(65535 - extra, extra, extra, reversed);
    }
    /* The first fragment's longer extension header must not be lost when the
     * continuation advertises a smaller unfragmentable part. */
    failed += run(65495, 8, 0, 0); failed += run(65495, 8, 0, 1);
    udp_remove(pcb); netif_remove(&iface); lwip_fini();
    puts("IPv6 reassembly length boundaries finished");
    return failed != 0;
}

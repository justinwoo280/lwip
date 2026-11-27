/* A duplicate/overlap at a full budget must not evict another interface's data. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/inet_chksum.h>
#include <lwip/udp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }
static struct netif interfaces[2];
static ip_addr_t source, destination;
static u8_t datagrams[2][2048];
static unsigned received;
static void be16(u8_t *p, unsigned n) { p[0]=(u8_t)(n>>8); p[1]=(u8_t)n; }
static err_t output4(struct netif *n, struct pbuf *p, const ip4_addr_t *a) {
    (void)n; (void)p; (void)a; return ERR_OK;
}
static err_t output6(struct netif *n, struct pbuf *p, const ip6_addr_t *a) {
    (void)n; (void)p; (void)a; return ERR_OK;
}
static err_t init_if(struct netif *n) {
    n->mtu=1500; n->output=output4; n->output_ip6=output6; return ERR_OK;
}
static void recv_udp(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *a, u16_t port) {
    u8_t bytes[40]; (void)arg; (void)pcb; (void)a;
    assert(ip_current_input_netif()==&interfaces[0] && port==40000 && p->tot_len==sizeof(bytes));
    assert(pbuf_copy_partial(p,bytes,sizeof(bytes),0)==sizeof(bytes));
    assert(!memcmp(bytes,datagrams[0]+8,sizeof(bytes)));
    received++; pbuf_free(p);
}
static void input(unsigned iface, int v6, unsigned offset, int more) {
    u8_t bytes[64]={0};
    unsigned hlen=v6?48:20;
    if (v6) {
        bytes[0]=0x60; be16(bytes+4,24); bytes[6]=44; bytes[7]=64;
        memcpy(bytes+8,ip_2_ip6(&source)->addr,16); memcpy(bytes+24,ip_2_ip6(&destination)->addr,16);
        bytes[40]=17; be16(bytes+42,offset|(more?1:0)); be16(bytes+46,0x1234+iface);
    } else {
        bytes[0]=0x45; be16(bytes+2,36); be16(bytes+4,0x1234+iface);
        be16(bytes+6,(offset/8)|(more?0x2000:0)); bytes[8]=64; bytes[9]=17;
        memcpy(bytes+12,&ip_2_ip4(&source)->addr,4); memcpy(bytes+16,&ip_2_ip4(&destination)->addr,4);
        u16_t sum=inet_chksum(bytes,20); memcpy(bytes+10,&sum,2);
    }
    memcpy(bytes+hlen,datagrams[iface]+offset,16);
    struct pbuf *p=pbuf_alloc(PBUF_RAW,(u16_t)(hlen+16),PBUF_RAM); assert(p);
    assert(pbuf_take(p,bytes,hlen+16)==ERR_OK);
    assert(ip_input(p,&interfaces[iface])==ERR_OK);
}
static int run(int v6, int overlap) {
    lwip_init(); received=0; memset(interfaces,0,sizeof(interfaces));
    assert(IP_REASS_MAX_PBUFS>=4 && IP_REASS_MAX_PBUFS<=128);
    assert(ipaddr_aton(v6?"fd00::10":"198.18.0.10",&source));
    assert(ipaddr_aton(v6?"fd00::20":"198.18.0.20",&destination));
    for (unsigned i=0;i<2;i++) {
        struct netif *n=&interfaces[i];
        assert(netif_add_noaddr(n,NULL,init_if,ip_input));
        if (v6) {
            s8_t idx; assert(netif_add_ip6_address(n,ip_2_ip6(&destination),&idx)==ERR_OK);
            netif_ip6_addr_set_state(n,idx,IP6_ADDR_PREFERRED);
        } else {
            ip4_addr_t mask,gw; IP4_ADDR(&mask,255,255,255,0); ip4_addr_set_zero(&gw);
            netif_set_addr(n,ip_2_ip4(&destination),&mask,&gw);
        }
        netif_set_up(n); netif_set_link_up(n); netif_set_default(n);
        unsigned len=i?(IP_REASS_MAX_PBUFS-1)*16:48;
        u8_t *d=datagrams[i]; memset(d,0,len);
        be16(d,40000); be16(d+2,1234); be16(d+4,len);
        for (unsigned j=8;j<len;j++) d[j]=(u8_t)(j*23+i);
        struct pbuf *p=pbuf_alloc(PBUF_RAW,(u16_t)len,PBUF_RAM); assert(p);
        assert(pbuf_take(p,d,len)==ERR_OK);
        u16_t sum=ip_chksum_pseudo(p,17,(u16_t)len,&source,&destination);
        if (!sum) sum=0xffff;
        memcpy(d+6,&sum,2); pbuf_free(p);
    }
    struct udp_pcb *pcb=udp_new_ip_type(IP_GET_TYPE(&destination)); assert(pcb);
    assert(udp_bind(pcb,v6?IP6_ADDR_ANY:IP_ADDR_ANY,1234)==ERR_OK); udp_recv(pcb,recv_udp,NULL);
    input(0,v6,0,1); input(0,v6,16,1);
    for (unsigned i=0;i<IP_REASS_MAX_PBUFS-2;i++) input(1,v6,i*16,1);
    input(1,v6,overlap?8:0,1);
    /* Closing B releases its own budget. A's pending datagram must still exist. */
    if (v6) ip6_reass_remove_netif(&interfaces[1]);
    else ip_reass_remove_netif(&interfaces[1]);
    netif_remove(&interfaces[1]);
    input(0,v6,32,0);
    printf("IPv%d full-budget %s: intact_datagrams=%u\n",v6?6:4,overlap?"overlap":"duplicate",received);
    int failed=received!=1;
    udp_remove(pcb); netif_remove(&interfaces[0]); lwip_fini();
    return failed;
}
int main(void) {
    int failed=0;
    for (int v6=0;v6<2;v6++) for (int overlap=0;overlap<2;overlap++) failed+=run(v6,overlap);
    return failed!=0;
}

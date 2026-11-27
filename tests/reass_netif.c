/* Delayed ICMP replies must retain the fragment queue's input interface. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/inet_chksum.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }
static struct netif interfaces[2];
static unsigned replies[2];
static void be16(u8_t *p,unsigned n) { p[0]=(u8_t)(n>>8); p[1]=(u8_t)n; }
static err_t output4(struct netif *n,struct pbuf *p,const ip4_addr_t *dest) {
    u8_t h[28]; (void)dest;
    assert(pbuf_copy_partial(p,h,sizeof(h),0)==sizeof(h));
    assert(h[9]==1 && h[20]==11 && h[21]==1 && inet_chksum(h,20)==0);
    replies[n==&interfaces[1]]++;
    return ERR_OK;
}
static err_t output6(struct netif *n,struct pbuf *p,const ip6_addr_t *dest) {
    u8_t h[48]; (void)dest;
    assert(pbuf_copy_partial(p,h,sizeof(h),0)==sizeof(h));
    assert(h[6]==58 && h[40]==3 && h[41]==1);
    replies[n==&interfaces[1]]++;
    return ERR_OK;
}
static err_t init_if(struct netif *n) {
    n->mtu=1500; n->output=output4; n->output_ip6=output6; return ERR_OK;
}
static void first_fragment(int v6) {
    u8_t packet[64]={0};
    unsigned iplen=v6?48:20;
    if (v6) {
        packet[0]=0x60; packet[6]=44; packet[7]=64; be16(packet+4,24);
        packet[8]=0xfd; packet[23]=10; packet[24]=0xfd; packet[39]=20;
        packet[40]=17; be16(packet+42,1); packet[47]=42;
    } else {
        packet[0]=0x45; packet[8]=64; packet[9]=17; be16(packet+2,36);
        be16(packet+4,42); be16(packet+6,0x2000);
        packet[12]=198; packet[13]=18; packet[15]=10;
        packet[16]=198; packet[17]=18; packet[19]=20;
        u16_t sum=inet_chksum(packet,20); memcpy(packet+10,&sum,2);
    }
    be16(packet+iplen,40000); be16(packet+iplen+2,1234); be16(packet+iplen+4,32);
    struct pbuf *p=pbuf_alloc(PBUF_RAW,(u16_t)(iplen+16),PBUF_RAM); assert(p);
    assert(pbuf_take(p,packet,iplen+16)==ERR_OK);
    assert(ip_input(p,&interfaces[0])==ERR_OK);
}
static int run(int v6) {
    lwip_init();
    memset(interfaces,0,sizeof(interfaces)); memset(replies,0,sizeof(replies));
    for (unsigned i=0;i<2;i++) {
        ip4_addr_t a,zero;
        IP4_ADDR(&a,127,0,0,1); ip4_addr_set_zero(&zero);
        struct netif *n=&interfaces[i];
        assert(netif_add(n,&a,&zero,&zero,NULL,init_if,ip_input));
        netif_set_up(n); netif_set_link_up(n); netif_set_default(n);
        netif_set_flags(n,NETIF_FLAG_PRETEND_UDP);
    }
    first_fragment(v6);
    for (unsigned i=0;i<=(v6?IPV6_REASS_MAXAGE:IP_REASS_MAXAGE);i++) {
        if (v6) ip6_reass_tmr(); else ip_reass_tmr();
    }
    printf("IPv%d timeout reply: owner=%u other_netif=%u\n",v6?6:4,replies[0],replies[1]);
    int failed=replies[0]!=1 || replies[1]!=0;
    netif_remove(&interfaces[0]); netif_remove(&interfaces[1]); lwip_fini();
    return failed;
}
int main(void) { int failed=run(0); failed+=run(1); return failed!=0; }

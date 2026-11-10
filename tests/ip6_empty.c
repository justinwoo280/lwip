/* A valid fragment stored in a pbuf chain larger than the configured
 * reassembly budget must be dropped without leaving an empty queue entry. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip6_frag.h>
#include <lwip/inet_chksum.h>
#include <lwip/netif.h>
#include <lwip/udp.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }
static struct netif iface;
static unsigned received;
static unsigned live_allocations;
static uint8_t datagram[96];
static ip6_addr_t source, destination;

/* Count lwIP allocations independently of sanitizer reachability. */
void *hev_malloc(size_t n) {
    void *p=malloc(n); if (p) live_allocations++; return p;
}
void *hev_calloc(size_t n,size_t size) {
    void *p=calloc(n,size); if (p) live_allocations++; return p;
}
void hev_free(void *p) {
    if (p) { assert(live_allocations); live_allocations--; free(p); }
}

static err_t output6(struct netif *n, struct pbuf *p, const ip6_addr_t *addr) {
    (void)n; (void)p; (void)addr; return ERR_OK;
}
static err_t init_if(struct netif *n) {
    n->mtu=1500; n->output_ip6=output6; return ERR_OK;
}
static void receive(void *arg,struct udp_pcb *pcb,struct pbuf *p,const ip_addr_t *a,u16_t port) {
    uint8_t bytes[sizeof(datagram)-8];
    (void)arg; (void)pcb;
    assert(p && p->tot_len==sizeof(bytes) && port==40000);
    assert(IP_IS_V6(a) && ip6_addr_cmp(ip_2_ip6(a),&source));
    assert(pbuf_copy_partial(p,bytes,sizeof(bytes),0)==sizeof(bytes));
    assert(!memcmp(bytes,datagram+8,sizeof(bytes)));
    received++; pbuf_free(p);
}
static void be16(uint8_t *p,unsigned n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }
static void input(unsigned chain_count,unsigned id,unsigned offset,unsigned length,int more) {
    uint8_t bytes[128]={0};
    unsigned total=48+length;
    assert(length<=80 && offset%8==0 && (!more || length%8==0));
    bytes[0]=0x60; be16(bytes+4,8+length); bytes[6]=44; bytes[7]=64;
    memcpy(bytes+8,source.addr,16); memcpy(bytes+24,destination.addr,16);
    bytes[40]=17; be16(bytes+42,offset|(more?1:0));
    bytes[46]=(uint8_t)(id>>8); bytes[47]=(uint8_t)id;
    memcpy(bytes+48,datagram+(offset<sizeof(datagram)?offset:0),length);
    struct pbuf *head=NULL;
    unsigned copied=0;
    for (unsigned i=0;i<chain_count;i++) {
        unsigned n=i==0?total-(chain_count-1)*8:8;
        assert(n>=8 && copied+n<=total);
        struct pbuf *p=pbuf_alloc(PBUF_RAW,(u16_t)n,PBUF_RAM); assert(p);
        assert(pbuf_take(p,bytes+copied,(u16_t)n)==ERR_OK);
        if (head) pbuf_cat(head,p); else head=p;
        copied+=n;
    }
    assert(copied==total && head->len>=48 && pbuf_clen(head)==chain_count);
    assert(ip_input(head,&iface)==ERR_OK);
}
static void expire(void) {
    for (unsigned i=0;i<=IPV6_REASS_MAXAGE;i++) ip6_reass_tmr();
}
int main(int argc,char **argv) {
    unsigned chain_count=argc>1?(unsigned)strtoul(argv[1],NULL,10):IP_REASS_MAX_PBUFS+1;
    assert(chain_count>0 && chain_count<=9);
    setvbuf(stdout,NULL,_IONBF,0);
    lwip_init();
    assert(netif_add_noaddr(&iface,NULL,init_if,ip_input));
    assert(ip6addr_aton("fd00::10",&source) && ip6addr_aton("fd00::20",&destination));
    s8_t index; assert(netif_add_ip6_address(&iface,&destination,&index)==ERR_OK);
    netif_ip6_addr_set_state(&iface,index,IP6_ADDR_PREFERRED);
    netif_set_up(&iface); netif_set_link_up(&iface); netif_set_default(&iface);
    struct udp_pcb *pcb=udp_new_ip_type(IPADDR_TYPE_V6); assert(pcb);
    assert(udp_bind(pcb,IP6_ADDR_ANY,1234)==ERR_OK); udp_recv(pcb,receive,NULL);
    be16(datagram,40000); be16(datagram+2,1234); be16(datagram+4,sizeof(datagram));
    for (unsigned i=8;i<sizeof(datagram);i++) datagram[i]=(uint8_t)(i*37+11);
    struct pbuf *whole=pbuf_alloc(PBUF_RAW,sizeof(datagram),PBUF_RAM); assert(whole);
    assert(pbuf_take(whole,datagram,sizeof(datagram))==ERR_OK);
    uint16_t sum=ip6_chksum_pseudo(whole,17,sizeof(datagram),&source,&destination);
    if (!sum) sum=0xffff;
    memcpy(datagram+6,&sum,2); pbuf_free(whole);
    unsigned base=live_allocations;

    /* Exercise the rejection path before a reassembly entry is allocated. */
    input(1,0x5370,65528,80,1);
    assert(live_allocations==base);
    printf("IPv6 fragment: chain=%u budget=%u\n",chain_count,(unsigned)IP_REASS_MAX_PBUFS);
    input(chain_count,0x5371,0,80,1);
    printf("retained allocations after input=%u\n",live_allocations-base);
    puts("input returned; expiring reassembly queues");
    expire();
    assert(live_allocations==base);
    assert(received==0);

#if !IP_REASS_FREE_OLDEST
    /* Fill the budget with two valid queues, then reject a new queue's
     * first fragment. This uses only one pbuf for the rejected packet. */
    input(3,0x5380,0,80,1); input(1,0x5381,0,80,1);
    assert(live_allocations==base+6);
    input(1,0x5382,0,80,1);
    assert(live_allocations==base+6);
    expire(); assert(live_allocations==base);
#endif

    /* The first-fragment cleanup must not remove an established queue when
     * rejecting duplicates, overlaps, or an over-budget continuation. */
    input(1,0x5371,0,80,1);
    input(1,0x5371,0,80,1); /* duplicate */
    input(1,0x5371,8,80,1); /* overlap */
    input(5,0x5371,16,80,0); /* too many buffers */
    assert(live_allocations==base+2);
    input(1,0x5371,80,16,0);
    assert(received==1 && live_allocations==base);
    /* Also complete a datagram with its last fragment arriving first. */
    input(1,0x5372,80,16,0); input(1,0x5372,0,80,1);
    assert(received==2 && live_allocations==base);
    /* Reinitialization must remain safe after the dropped fragment. */
    udp_remove(pcb); netif_remove(&iface); lwip_fini();
    assert(live_allocations==0);
    lwip_init(); lwip_fini();
    puts("IPv6 reassembly timeout/cleanup PASS");
    return 0;
}

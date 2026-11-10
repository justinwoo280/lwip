/* Standalone packet-level regression for RFC 791 fragment identity.
 * All source datagrams and fragment headers have valid checksums. */
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/udp.h>
#include <lwip/inet_chksum.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int lwip_port_rand(void) { return (unsigned int)rand(); }
u32_t sys_now(void) { return 0; }

static struct netif iface;
static ip4_addr_t source, destination;
static unsigned udp_received, echo_received, corrupt, time_exceeded;
static uint8_t udp_datagram[48], icmp_datagram[48];

static void be16(uint8_t *p, unsigned value) {
    p[0]=(uint8_t)(value>>8); p[1]=(uint8_t)value;
}
static unsigned read16(const uint8_t *p) { return ((unsigned)p[0]<<8)|p[1]; }

static err_t output4(struct netif *n, struct pbuf *p, const ip4_addr_t *addr) {
    uint8_t bytes[128];
    unsigned length=p->tot_len;
    (void)n; (void)addr;
    assert(length<=sizeof(bytes));
    assert(pbuf_copy_partial(p,bytes,(u16_t)length,0)==length);
    unsigned hlen=(bytes[0]&15)*4;
    assert(hlen>=20 && length>=hlen+8 && bytes[9]==1);
    if (bytes[hlen]==0) {
        echo_received++;
        if (length!=20+sizeof(icmp_datagram) ||
            memcmp(bytes+hlen+4,icmp_datagram+4,sizeof(icmp_datagram)-4) ||
            inet_chksum(bytes+hlen,(u16_t)(length-hlen))!=0) corrupt++;
    } else if (bytes[hlen]==11) {
        time_exceeded++;
    } else {
        corrupt++;
    }
    return ERR_OK;
}
static err_t init_if(struct netif *n) {
    n->mtu=1500; n->output=output4; return ERR_OK;
}
static void receive(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                    const ip_addr_t *addr, u16_t port) {
    uint8_t bytes[64];
    (void)arg; (void)pcb;
    assert(p && p->tot_len<=sizeof(bytes));
    udp_received++;
    unsigned n=pbuf_copy_partial(p,bytes,p->tot_len,0);
    if (n!=sizeof(udp_datagram)-8 || memcmp(bytes,udp_datagram+8,n) ||
        port!=40000 || !IP_IS_V4(addr) || !ip4_addr_eq(ip_2_ip4(addr),&source)) corrupt++;
    pbuf_free(p);
}
static void prepare(void) {
    struct udp_pcb *pcb;
    ip4_addr_t mask,gw;
    lwip_init();
    memset(&iface,0,sizeof(iface));
    IP4_ADDR(&source,198,18,0,10); IP4_ADDR(&destination,198,18,0,20);
    IP4_ADDR(&mask,255,255,255,0); ip4_addr_set_zero(&gw);
    assert(netif_add(&iface,&destination,&mask,&gw,NULL,init_if,ip_input));
    netif_set_default(&iface); netif_set_up(&iface); netif_set_link_up(&iface);
    pcb=udp_new_ip_type(IPADDR_TYPE_V4); assert(pcb);
    assert(udp_bind(pcb,IP_ADDR_ANY,1234)==ERR_OK);
    udp_recv(pcb,receive,NULL);
    udp_received=echo_received=corrupt=time_exceeded=0;
}
static void finish(void) {
    while (udp_pcbs) udp_remove(udp_pcbs);
    netif_remove(&iface); lwip_fini();
}
static void make_datagrams(void) {
    memset(udp_datagram,0,sizeof(udp_datagram));
    memset(icmp_datagram,0,sizeof(icmp_datagram));
    be16(udp_datagram,40000); be16(udp_datagram+2,1234);
    be16(udp_datagram+4,sizeof(udp_datagram));
    icmp_datagram[0]=8; be16(icmp_datagram+4,0x1257); be16(icmp_datagram+6,7);
    for (unsigned i=8;i<sizeof(udp_datagram);i++) {
        udp_datagram[i]=(uint8_t)(i*17+3);
        icmp_datagram[i]=(uint8_t)(i*31+11);
    }
    struct pbuf *p=pbuf_alloc(PBUF_RAW,sizeof(udp_datagram),PBUF_RAM); assert(p);
    assert(pbuf_take(p,udp_datagram,sizeof(udp_datagram))==ERR_OK);
    uint16_t sum=inet_chksum_pseudo(p,17,sizeof(udp_datagram),&source,&destination);
    if (!sum) sum=0xffff;
    memcpy(udp_datagram+6,&sum,2); pbuf_free(p);
    sum=inet_chksum(icmp_datagram,sizeof(icmp_datagram)); memcpy(icmp_datagram+2,&sum,2);
    assert(inet_chksum(icmp_datagram,sizeof(icmp_datagram))==0);
}
static void input(unsigned proto,unsigned id,const uint8_t *payload,
                  unsigned offset,unsigned length,int more) {
    uint8_t bytes[128]={0};
    assert(offset%8==0 && (!more || length%8==0) && 20+length<=sizeof(bytes));
    bytes[0]=0x45; bytes[8]=64; bytes[9]=(uint8_t)proto;
    be16(bytes+2,20+length); be16(bytes+4,id); be16(bytes+6,(offset/8)|(more?0x2000:0));
    memcpy(bytes+12,&source.addr,4); memcpy(bytes+16,&destination.addr,4);
    memcpy(bytes+20,payload+offset,length);
    uint16_t sum=inet_chksum(bytes,20); memcpy(bytes+10,&sum,2);
    assert(inet_chksum(bytes,20)==0 && read16(bytes+2)==20+length);
    struct pbuf *p=pbuf_alloc(PBUF_RAW,(u16_t)(20+length),PBUF_RAM); assert(p);
    assert(pbuf_take(p,bytes,(u16_t)(20+length))==ERR_OK);
    assert(ip_input(p,&iface)==ERR_OK);
}
static int permutation(const unsigned order[4],int shared_id) {
    prepare(); make_datagrams();
    for (unsigned i=0;i<4;i++) {
        unsigned item=order[i], proto=item<2?17:1;
        unsigned id=(shared_id || item<2)?0x5371:0x5372;
        input(proto,id,item<2?udp_datagram:icmp_datagram,
              item%2?16:0,item%2?32:16,item%2==0);
    }
    int failed=udp_received!=1 || echo_received!=1 || corrupt!=0;
    if (failed) printf("id=%s order=%u%u%u%u UDP=%u echo=%u corrupt=%u\n",
                       shared_id?"same":"different",order[0],order[1],order[2],order[3],
                       udp_received,echo_received,corrupt);
    finish(); return failed;
}
static int pressure(void) {
    uint8_t pending_udp[80]={0};
    prepare(); make_datagrams();
    be16(pending_udp,40000); be16(pending_udp+2,1234); be16(pending_udp+4,sizeof(pending_udp));
    /* An incomplete UDP datagram fills the four-pbuf budget. An unrelated
     * ICMP datagram with the same addresses/ID must be eligible to evict it. */
    for (unsigned offset=0;offset<64;offset+=16) input(17,0x5371,pending_udp,offset,16,1);
    input(1,0x5371,icmp_datagram,0,16,1);
    input(1,0x5371,icmp_datagram,16,32,0);
    int failed=udp_received!=0 || echo_received!=1 || corrupt!=0 || time_exceeded!=1;
    printf("pressure UDP=%u echo=%u corrupt=%u time_exceeded=%u\n",
           udp_received,echo_received,corrupt,time_exceeded);
    finish(); return failed;
}
int main(void) {
    unsigned shared_fail=0,control_fail=0;
    for (unsigned a=0;a<4;a++) for (unsigned b=0;b<4;b++)
    for (unsigned c=0;c<4;c++) for (unsigned d=0;d<4;d++) {
        if (a==b || a==c || a==d || b==c || b==d || c==d) continue;
        unsigned order[]={a,b,c,d};
        control_fail+=permutation(order,0);
        shared_fail+=permutation(order,1);
    }
    unsigned pressure_fail=pressure();
    printf("IPv4 protocol isolation: control_fail=%u/24 shared_id_fail=%u/24 pressure_fail=%u\n",
           control_fail,shared_fail,pressure_fail);
    return control_fail || shared_fail || pressure_fail ? 1:0;
}

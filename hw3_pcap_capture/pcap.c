#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<pcap.h>
#include<time.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#define SNAP_LEN 2048

typedef struct eth_hdr
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}eth_hdr;
eth_hdr *ethernet;

typedef struct ip_hdr
{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}ip_hdr;
ip_hdr *ip;

typedef struct tcp_hdr
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
}tcp_hdr;
tcp_hdr *tcp;

typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
}udp_hdr;
udp_hdr *udp;

void my_pcap_handler(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

int main(int argc, char *argv[])
{
    char *dev, errbuf[1024];
    struct in_addr addr;
    bpf_u_int32 ipaddress, ipmask;
    char *dev_ip, *dev_mask;

    if(argc < 2 || argc > 3){
        printf("for offline usage: ./pcap [filename.pcap]\n");
        printf("for online usage: ./pcap [device] [filter]\n");
        return 0;
    }

    dev = argv[1];
    if(dev == NULL){
        printf("device not found\n");
        return 0;
    }

    if(argc == 2){
        pcap_t *pcap = pcap_open_offline(dev, errbuf);
        if(pcap == NULL){
            printf("%s\n", errbuf);
            return 0;
        }

        pcap_dumper_t* dumpfp = pcap_dump_open(pcap, "./save.pcap");
        if(pcap_loop(pcap, -1, my_pcap_handler, (unsigned char *)dumpfp) < 0){
            printf("error in loop\n");
            return 0;
        }

        pcap_dump_close(dumpfp);
        pcap_close(pcap);
    }
    else{
        struct in_addr addr;
        bpf_u_int32 ipaddress, ipmask;
        char *dev_ip, *dev_mask;

        pcap_t *pcap = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if(pcap_lookupnet(dev, &ipaddress, &ipmask, errbuf) == -1){
            printf("%s\n", errbuf);
            return 0;
        }

        addr.s_addr = ipaddress;
        dev_ip = inet_ntoa(addr);
        // printf("ip address: %s\n", dev_ip);
        addr.s_addr = ipmask;
        dev_mask = inet_ntoa(addr);
        // printf("netmask: %s\n", dev_mask);

        struct bpf_program fp;
        if(pcap_compile(pcap, &fp, argv[2], 1, 0) < 0){
            printf("error in complie\n");
            return 0;
        }
        if(pcap_setfilter(pcap, &fp) < 0){
            printf("error in setfilter\n");
            return 0;
        }

        pcap_dumper_t* dumpfp = pcap_dump_open(pcap, "./save.pcap");
        if(pcap_loop(pcap, -1, my_pcap_handler, (unsigned char *)dumpfp) < 0){
            printf("error in loop\n");
            return 0;
        }
        
        pcap_dump_close(dumpfp);
        pcap_close(pcap);
    }

    return 0;
}

void my_pcap_handler(unsigned char *arg, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
    static int cnt = 0;
    u_int ip_len = sizeof(struct ip_hdr);
    u_int eth_len = sizeof(struct eth_hdr);
    u_int tcp_len = sizeof(struct tcp_hdr);
    u_int udp_len = sizeof(struct udp_hdr);

    printf("packet number: %d\n", cnt++);

    pcap_dump(arg, packet_header, packet_content);

    printf("Arrival time: %s", ctime((const time_t*)&packet_header->ts.tv_sec));
    printf("Length: %d\n", packet_header->len);
    // printf("Bytes: %d\n", packet_header->caplen);

    ethernet=(eth_hdr *)packet_content;
    printf("Ethernet Type: %u\n", ntohs(ethernet->eth_type));
    printf("MAC source address: %02x-%02x-%02x-%02x-%02x-%02x\n", ethernet->src_mac[0], ethernet->src_mac[1], ethernet->src_mac[2], ethernet->src_mac[3], ethernet->src_mac[4], ethernet->src_mac[5]);
    printf("MAC destination address: %02x-%02x-%02x-%02x-%02x-%02x\n", ethernet->dst_mac[0], ethernet->dst_mac[1], ethernet->dst_mac[2], ethernet->dst_mac[3], ethernet->dst_mac[4], ethernet->dst_mac[5]);

    if(ntohs(ethernet->eth_type) == 0x0800){
        ip=(ip_hdr*)(packet_content+eth_len);
        printf("IP source address: %d.%d.%d.%d\n", ip->sourceIP[0], ip->sourceIP[1], ip->sourceIP[2], ip->sourceIP[3]);
        printf("IP destination address: %d.%d.%d.%d\n", ip->destIP[0], ip->destIP[1], ip->destIP[2], ip->destIP[3]);
        
        if(ip->protocol == IPPROTO_TCP){
            tcp=(tcp_hdr*)(packet_content + eth_len + ip_len);
            printf("Protocol: TCP\n");
            printf("Source port: %d\n", ntohs(tcp->sport));
            printf("Destination port: %d\n", ntohs(tcp->dport));
        }
        else if(ip->protocol == IPPROTO_UDP){
            udp=(udp_hdr*)(packet_content + eth_len + ip_len);
            printf("Protocol: UDP\n");
            printf("Source port: %u\n", ntohs(udp->sport));
            printf("Destination port: %u\n", ntohs(udp->dport));
        }
        else if(ip->protocol == IPPROTO_IP){
            printf("Protocol: IP\n");
        }
        else if(ip->protocol == IPPROTO_ICMP){
            printf("Protocol: ICMP\n");
        }
        else{
            printf("Protocol: Unknown\n");
        }
    }

    printf("Content:\n");
    for(int i = 0; i < packet_header->caplen; i++){
        printf("%02x ", packet_content[i]);
        if((i + 1) % 16 == 0){
            printf("\n");
        }
    }
    printf("\n");

    printf("\n");
}
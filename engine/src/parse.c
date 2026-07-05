#include "../include/parse.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

int parse_packet(const unsigned char *packet, uint32_t caplen, packet_info *out) {
    if (caplen < sizeof(struct ether_header)) {
        return -1;
    }

    const struct ether_header *eth = (const struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return -1;
    }

    uint32_t offset = sizeof(struct ether_header);
    if (caplen < offset + sizeof(struct iphdr)) {
        return -1;
    }

    const struct iphdr *ip = (const struct iphdr *)(packet + offset);
    int ip_hdr_len = ip->ihl * 4;

    if (ip_hdr_len < (int)sizeof(struct iphdr)) {
        return -1;
    }
    if (caplen < offset + ip_hdr_len) {
        return -1;
    }

    out->src_ip = ip->saddr;
    out->dst_ip = ip->daddr;
    out->length = caplen;
    offset = offset + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (caplen < offset + sizeof(struct tcphdr))
            return -1;
        const struct tcphdr *tcp = (const struct tcphdr *)(packet + offset);
        out->proto = PROTO_TCP;
        out->src_port = ntohs(tcp->source);
        out->dst_port = ntohs(tcp->dest);
        return 0;
    } else if (ip->protocol == IPPROTO_UDP) {
        if (caplen < offset + sizeof(struct udphdr))
            return -1;
        const struct udphdr *udp = (const struct udphdr *)(packet + offset);
        out->proto = PROTO_UDP;
        out->src_port = ntohs(udp->source);
        out->dst_port = ntohs(udp->dest);
        return 0;
    }

    return -1;
}

void ip_to_str(uint32_t ip_net_order, char *buf, size_t buflen) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_net_order;
    inet_ntop(AF_INET, &ip_addr, buf, buflen);
}
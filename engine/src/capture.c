#include "../include/parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

static void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;

    packet_info pkt;
    if (parse_packet(packet, header->caplen, &pkt) != 0)
        return;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    ip_to_str(pkt.src_ip, src_ip, sizeof(src_ip));
    ip_to_str(pkt.dst_ip, dst_ip, sizeof(dst_ip));

    printf("%s  %s:%u -> %s:%u  (%u bytes)\n",
           pkt.proto == PROTO_TCP ? "TCP" : "UDP",
           src_ip, pkt.src_port,
           dst_ip, pkt.dst_port,
           pkt.length);
}
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    char *dev = NULL;
    if (argc > 1) {
        dev = argv[1];
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "No interfaces found: %s\n", errbuf);
            return 1;
        }
        dev = strdup(alldevs->name);
        pcap_freealldevs(alldevs);
    }
    printf("Listening on interface: %s\n", dev);

    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Cannot open %s: %s\n", dev, errbuf);
        fprintf(stderr, "Did you run with sudo?\n");
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface is not Ethernet; offsets would be incorrect.\n");
        pcap_close(handle);
        return 1;
    }

    struct bpf_program filter;
    const char *filter_exp = "tcp or udp";
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Invalid filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Cannot set filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&filter);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&filter);

    printf("Capturing...\n\n");
    pcap_loop(handle, -1, on_packet, NULL);
    pcap_close(handle);
    return 0;
}
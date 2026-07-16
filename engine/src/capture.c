#include "../include/parse.h"
#include "../include/flow.h"
#include "../include/engine.h"
#include "../include/sketch/cms.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>

static void on_sigint(int sig) {
    (void)sig;
    engine_stop();
}

void on_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_t *pkt = (packet_t *)user;
    packet_info p;
    if (parse_packet(packet, header->caplen, &p) != 0) {
        return;
    }

    flow_table_update(pkt->ft, &p, header->ts.tv_sec);
    cms_add(pkt->c, &p.src_ip, sizeof(p.src_ip), 1);
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
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        pcap_close(handle);
        return 1;
    }

    flow_table ft;
    flow_table_init(&ft);

    count_min_sketch c;
    if (cms_init(&c, 4, 2048) != 0) {
        pcap_close(handle);
        return 1;
    }

    signal(SIGINT, on_sigint);
    engine_run(handle, &ft, &c, 5, 60);
    
    flow_table_free(&ft);
    cms_free(&c);
    pcap_close(handle);
    return 0;
}
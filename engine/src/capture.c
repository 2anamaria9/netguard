#include "../include/parse.h"
#include "../include/flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/types.h>
#include <signal.h>

typedef struct {
    flow_table *ft;
    uint64_t count;
} capture_context;

static pcap_t *global_handle = NULL;
static void on_sigint(int sig) {
    (void)sig;
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
}

static void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    capture_context *ctx = (capture_context *)args;
    packet_info p;
    if (parse_packet(packet, header->caplen, &p) != 0) {
        return;
    }

    flow_table_update(ctx->ft, &p, header->ts.tv_sec);
    ctx->count++;
    if (ctx->count % 100 == 0) {
        flow_table_print_top(ctx->ft, 10);
    }
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

    flow_table ft;
    flow_table_init(&ft);
    capture_context ctx;
    ctx.ft = &ft;
    ctx.count = 0;

    global_handle = handle;
    signal(SIGINT, on_sigint);

    printf("Capturing...\n\n");
    pcap_loop(handle, -1, on_packet, (u_char *)&ctx);
    flow_table_free(&ft);
    pcap_close(handle);
    return 0;
}
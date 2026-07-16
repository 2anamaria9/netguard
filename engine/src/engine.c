#include "../include/engine.h"
#include "../include/sketch/cms.h"

#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>

#define MAX_SOURCES 4096
static volatile sig_atomic_t global_stop = 0;

void engine_stop(void) {
    global_stop = 1;
}

static int periodic_timer(int interval) {
    int t = timerfd_create(CLOCK_MONOTONIC, 0);
    if (t == -1) {
        return -1;
    }

    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = interval;
    its.it_interval.tv_sec = interval;

    if (timerfd_settime(t, 0, &its, NULL) == -1) {
        close(t);
        return -1;
    }
    return t;
}

static void expire_flows(flow_table *ft, time_t now, int timeout) {
    flow_t *flow, *tmp;
    HASH_ITER(hh, ft->flows, flow, tmp) {
        if (now - flow->last_seen > timeout) {
            HASH_DEL(ft->flows, flow);
            free(flow);
            ft->count--;
        }
    }
}

static void print_top_talkers(const flow_table *ft, const count_min_sketch *c, int k) {
    printf("--- Top talkers (by packets, CMS estimate) ---\n");

    uint32_t ips[MAX_SOURCES];
    uint64_t counts[MAX_SOURCES];
    int n = 0;

    flow_t *flow, *tmp;
    HASH_ITER(hh, ft->flows, flow, tmp) {
        uint32_t ip = flow->key.src_ip;
        int seen = 0;
        for (int i = 0; i < n; i++) {
            if (ips[i] == ip) {
                seen = 1;
                break;
            }
        }
        if (seen || n >= MAX_SOURCES) {
            continue;
        }
        ips[n] = ip;
        counts[n] = cms_estimate(c, &ip, sizeof(ip));
        n++;
    }

    for (int i = 0; i < k && i < n; i++) {
        int max = -1;
        for (int j = 0; j < n; j++) {
            if (counts[j] != UINT64_MAX && (max == -1 || counts[j] > counts[max])) {
                max = j;
            }
        }
        if (max == -1) {
            break;
        }
        char s[INET_ADDRSTRLEN];
        ip_to_str(ips[max], s, sizeof(s));
        
        if (counts[max] == 0) {
            counts[max] = UINT64_MAX;
            continue;
        }
        
        printf("  %-16s %llu pkts\n", s, (unsigned long long)counts[max]);
        counts[max] = UINT64_MAX;
    }
}

int engine_run(pcap_t *handle, flow_table *ft, count_min_sketch *c, int report_interval, int flow_timeout) {
    global_stop = 0;
    packet_t pkt;
    pkt.ft = ft;
    pkt.c = c;

    int pfd = pcap_get_selectable_fd(handle);
    if (pfd == -1) {
        return -1;
    }

    int tfd = periodic_timer(report_interval);
    if (tfd == -1) {
        return -1;
    }

    int epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1");
        close(tfd);
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = pfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pfd, &ev) == -1) {
        close(tfd);
        close(epfd);
        return -1;
    }
    ev.events = EPOLLIN;
    ev.data.fd = tfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) == -1) {
        close(tfd);
        close(epfd);
        return -1;
    }

    printf("Capturing...\n");

    struct epoll_event events[8];
    while (!global_stop) {
        int n = epoll_wait(epfd, events, 8, 1000);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == pfd) {
                pcap_dispatch(handle, -1, on_packet, (u_char *)&pkt);
            } else if (fd == tfd) {
                uint64_t exp;
                ssize_t r = read(tfd, &exp, sizeof(exp));
                (void)r;
                time_t now = time(NULL);
                flow_table_print_top(ft, 10);
                print_top_talkers(ft, c, 5);
                expire_flows(ft, now, flow_timeout);
                cms_reset(c);
            }
        }
    }

    printf("\nShutting down\n");
    close(tfd);
    close(epfd);
    return 0;
}


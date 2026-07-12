#include "../include/engine.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <errno.h>

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

int engine_run(pcap_t *handle, flow_table *ft, int report_interval, int flow_timeout) {
    global_stop = 0;
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
                pcap_dispatch(handle, -1, on_packet, (u_char *)ft);
            } else if (fd == tfd) {
                uint64_t exp;
                ssize_t r = read(tfd, &exp, sizeof(exp));
                (void)r;
                time_t now = time(NULL);
                flow_table_print_top(ft, 10);
                expire_flows(ft, now, flow_timeout);
            }
        }
    }

    printf("\nShutting down\n");
    close(tfd);
    close(epfd);
    return 0;
}


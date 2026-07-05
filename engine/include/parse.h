#ifndef PARSE_H
#define PARSE_H

#include <stdint.h>
#include <netinet/in.h> 

typedef enum {
    PROTO_TCP,
    PROTO_UDP,
} proto_t;

typedef struct {
    uint32_t src_ip;  
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    proto_t  proto;
    uint32_t length;
} packet_info;

int parse_packet(const unsigned char *packet, uint32_t caplen, packet_info *out);
void ip_to_str(uint32_t ip_net_order, char *buf, size_t buflen);

#endif
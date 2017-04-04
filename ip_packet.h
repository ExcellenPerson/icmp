#ifndef IP_PACKET_H
#define IP_PACKET_H
#include <arpa/inet.h>
struct ip_packet_t {
        uint8_t   vers_ihl,
                  tos;
        uint16_t  pkt_len,
                  id,
                  flags_frag_offset;
        uint8_t   ttl,
                  proto;  // 1 for ICMP                                              
        uint16_t  checksum;
        uint32_t  src_ip,
                  dst_ip;};

#define IPHDR_SIZE  sizeof(struct ip_packet_t)
int load_ip_packet_for_icmp( struct ip_packet_t *ip_pkt,
                             struct sockaddr_in *rsrc,
                             struct sockaddr_in *dest_addr);
#endif

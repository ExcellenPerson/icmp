#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H
#include <arpa/inet.h>
struct icmp_packet_t {
  uint8_t   type, code;
  uint16_t  checksum, identifier, seq;};

#define ICMPHDR_SIZE  sizeof(struct icmp_packet_t)


uint16_t calc_icmp_checksum(uint16_t *data,
                            int bytes);

int load_icmp_echo_request( struct icmp_packet_t *pkt);

int load_icmp_ttl_exceeded( struct icmp_packet_t *pkt);

#endif

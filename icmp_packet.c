#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h> /* IPPROTO_RAW def. */
#include <netinet/ip.h>

#include "icmp_packet.h"

/* Calculate ICMP checksum */
uint16_t calc_icmp_checksum(uint16_t *data,
                            int bytes){
  uint32_t sum;
  int i;
  sum = 0;
  for (i=0;i<bytes/2;i++) {
    sum += data[i];}
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = htons(0xFFFF - sum);
  return sum;}


/* load ICMP echo req*/
int load_icmp_echo_request( struct icmp_packet_t *pkt){
  memset(pkt, 0, ICMPHDR_SIZE);
  pkt->type = 8;//icmp echo request                                                                             
  pkt->code = 0; // no code                                                                                     
  pkt->identifier = 0;
  pkt->seq = 0;
  pkt->checksum = 0;
  pkt->checksum = htons(calc_icmp_checksum((uint16_t*)pkt, ICMPHDR_SIZE));
  return 1;}


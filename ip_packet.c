#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h> /* IPPROTO_RAW def. */
#include <netinet/ip.h>
#include "ip_packet.h"
#include "icmp_packet.h"
/* load IP packet with ICMP proto  */
int load_ip_packet_for_icmp( struct ip_packet_t *ip_pkt,
                             struct sockaddr_in *src_addr,
                             struct sockaddr_in *dest_addr){
  //make sure ip_pkt has malloc(IPHDR_SIZE + ICMPHDR_SIZE)                                                      
  int pkt_len = IPHDR_SIZE + ICMPHDR_SIZE;
  memset(ip_pkt, 0, pkt_len);
  ip_pkt->vers_ihl = 0x45;
  ip_pkt->tos = 0;
  ip_pkt->pkt_len = pkt_len;
  ip_pkt->id = 0;
  ip_pkt->flags_frag_offset = 0;
  ip_pkt->ttl = IPDEFTTL; // default ttl (64)                                                          
  ip_pkt->proto = 1; // ICMP                                                                                    
  ip_pkt->checksum = 0;// kernel handles this
  ip_pkt->src_ip = src_addr->sin_addr.s_addr; 
  ip_pkt->dst_ip = dest_addr->sin_addr.s_addr;
  return 1;}


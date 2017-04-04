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
                             struct sockaddr_in *rsrc,
                             struct sockaddr_in *dest_addr){
  //make sure ip_pkt has malloc(IPHDR_SIZE + ICMPHDR_SIZE)                                                      
  int pkt_len = IPHDR_SIZE + ICMPHDR_SIZE;
  memset(ip_pkt, 0, pkt_len);
  ip_pkt->vers_ihl = 0x45;
  ip_pkt->tos = 0;
  ip_pkt->pkt_len = pkt_len;
  ip_pkt->id = 1; //kernel sets proper value htons(ip_id_counter);                                              
  ip_pkt->flags_frag_offset = 0;
  ip_pkt->ttl = IPDEFTTL; // default time to live (64)                                                          
  ip_pkt->proto = 1; // ICMP                                                                                    
  ip_pkt->checksum = 0; // maybe the kernel helps us out..?                                                     
  ip_pkt->src_ip = rsrc->sin_addr.s_addr; // insert source IP address here                                      
  ip_pkt->dst_ip = dest_addr->sin_addr.s_addr;
  return 1;}


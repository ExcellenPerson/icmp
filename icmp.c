/*
 * code adapted from https://github.com/samyk/pwnat ( Samy Kamkar ), thanks!
 *
 * daniel saha - drs5ma@virgnia.edu
 * april 4 2017
 *
 *
 * 
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <netinet/in.h> /* IPPROTO_RAW def. */
#include <netinet/ip.h>
//#include "packet.h"
unsigned const int one = 1;

struct icmp_packet_t {
  uint8_t   type, code;
  uint16_t  checksum, identifier, seq;
};


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
	          dst_ip;
};

#define IPHDR_SIZE  sizeof(struct ip_packet_t)
#define ICMPHDR_SIZE  sizeof(struct icmp_packet_t)





/* Calculate ICMP checksum */
uint16_t calc_icmp_checksum(uint16_t *data,
			    int bytes){
  uint32_t sum;
  int i;
  sum = 0;
  for (i=0;i<bytes/2;i++) {
    sum += data[i];
  }
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = htons(0xFFFF - sum);
  return sum;}

/* create ICMP socket */ 
int create_icmp_socket(){
  int icmp_sock;
  icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (icmp_sock < 0){
      printf("Couldn't create privileged raw socket: %s\n", strerror(errno));
      return 0;}
  setsockopt(icmp_sock, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));
  setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL,(char *)&one, sizeof(one));
  return icmp_sock;}

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

/* */
int send_icmp_echorequest( int icmp_sock,
			   struct sockaddr_in *src_addr,
			   struct sockaddr_in *dest_addr){

  struct ip_packet_t* ip_pkt;
  struct icmp_packet_t* icmp_pkt;
  int pkt_len = IPHDR_SIZE + ICMPHDR_SIZE, err = 0;
  char *packet = malloc(pkt_len);
  memset(packet, 0, pkt_len);
  
  load_ip_packet_for_icmp((struct ip_packet_t*)packet, src_addr, dest_addr);
  load_icmp_echo_request((struct icmp_packet_t*)((packet+IPHDR_SIZE)));  
  err = sendto(icmp_sock,
	       packet,
	       pkt_len,
	       0,
	       (struct sockaddr*)dest_addr,
	       sizeof(struct sockaddr));
  free(packet);
  
  if (err < 0) {
    printf("Failed to send ICMP packet: %s\n", strerror(errno));
    exit(1);}
  else if (err != pkt_len){
    printf("didn't send entire packet\n");
    exit(1);}

  return 0;
}



int load_src(){
  return 0;
}

int main(int argc, char *argv[]){
  printf("usage: ./icmp <ip_address>\n");fflush(stdout);
  
  char *lhost, *lport, *phost, *pport, *rhost, *rport;
  char pport_s[6] = "2222";
  int i=0;
  uint32_t timeexc_ip;
  int icmp_sock = 0;
  struct sockaddr_in src, dest, rsrc;
  memset(&src, 0, sizeof(struct sockaddr_in));
  phost = "8.8.8.8";//"75.102.136.100";
  phost = argv[1];
  
  memset(&dest, 0, sizeof(struct sockaddr_in));

  dest.sin_family        = AF_INET;
  dest.sin_port          = 0;
  inet_pton(AF_INET, phost, &dest.sin_addr);
  /* open raw socket */
  icmp_sock = create_icmp_socket();

  /* make sure no socket errors */
  if (icmp_sock == -1) {
    printf("couldn't create icmp socket\n");
    exit(1);}
  
  /* send icmp echo request */
  send_icmp_echorequest(icmp_sock, &src, &dest);
  printf("Sent ICMP echo-request to %s\n", phost);
  fflush(stdout);
  return 0;
}

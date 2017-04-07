/*
 * code adapted from https://github.com/samyk/pwnat ( Samy Kamkar ), thanks!
 *
 * daniel saha - drs5ma@virgnia.edu
 * april 4 2017
 *
 *
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h> /* IPPROTO_RAW def. */
#include <netinet/ip.h>



#include "icmp_packet.h"
#include "ip_packet.h"


unsigned const int one = 1;

/* create ICMP socket for listening */
int create_icmp_listen_socket(){
  int listen_socket;
  listen_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (listen_socket < 0){
      printf("Couldn't create privileged raw socket: %s\n", strerror(errno));
      return 0;}
  /*if(fcntl(listen_socket, F_SETFL, O_NONBLOCK) == -1){
    printf("F_SETFL error: %s", strerror(errno));
    return 0;}*/
  return listen_socket;}

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


uint16_t calc_icmp_checksum(uint16_t *data, int bytes)
{
	uint32_t sum;
	int i;

	sum = 0;
	for (i=0;i<bytes/2;i++) {
		sum += data[i];
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = htons(0xFFFF - sum);
	return sum;
}
/* given a src and dest and open icmp socket, send echo-request */

double send_icmp_echorequest( int icmp_sock,
			   struct sockaddr_in *src_addr,
			   struct sockaddr_in *dest_addr){
  struct ip_packet_t* ip_pkt;
  struct icmp_packet_t* icmp_pkt;
  struct timeval t1,t2;
  double elapsed_time;
      int pkt_len = IPHDR_SIZE + ICMPHDR_SIZE, err = 0;
  char *packet = malloc(pkt_len);
  memset(packet, 0, pkt_len);

  
    
  load_ip_packet_for_icmp((struct ip_packet_t*)packet, src_addr, dest_addr, 0);
  load_icmp_echo_request((struct icmp_packet_t*)((packet+IPHDR_SIZE)));  

  err = sendto(icmp_sock,
	       packet,
	       pkt_len,
	       0,
	       (struct sockaddr*)dest_addr,
	       sizeof(struct sockaddr));
  //handle errors
  if (err < 0) {
    printf("Failed to send ICMP packet: %s\n", strerror(errno));
    exit(1);}
  else if (err != pkt_len){
    printf("didn't send entire packet\n");
    exit(1);}


  free(packet);
  return 0.0;}


/* given a src and dest and open icmp socket, send echo-request */
int send_icmp_ttlexceeded( int icmp_sock,
          			   struct sockaddr_in *src_addr,
          			   struct sockaddr_in *dest_addr){

            struct hostent *hp;
            struct ip_packet_t* ip_pkt;
            struct icmp_packet_t* icmp_pkt;
	    struct sockaddr_in dest;
            int pkt_len = 2*(IPHDR_SIZE + ICMPHDR_SIZE);
	    int err = 0;
            char *packet = malloc(pkt_len);
            memset(packet, 0, pkt_len);

	    hp = gethostbyname("3.3.3.3");
	    memcpy(&dest.sin_addr, hp->h_addr, hp->h_length); 
	    inet_pton(AF_INET, "3.3.3.3", &(dest.sin_addr));


	    struct ip_packet_t *ipptr;
	    struct icmp_packet_t *icmpptr;
	    //ip_pkt
            load_ip_packet_for_icmp((struct ip_packet_t*)packet, src_addr, dest_addr,0 );

	    //pkt
            load_icmp_ttl_exceeded((struct icmp_packet_t*)((packet+IPHDR_SIZE)));
	    //ip_pkt2
	    load_ip_packet_for_icmp((struct ip_packet_t*)((packet+IPHDR_SIZE+ICMPHDR_SIZE)), dest_addr, &dest, 1);
	    //pkt2
	    load_icmp_echo_request((struct icmp_packet_t*)((packet+IPHDR_SIZE+ICMPHDR_SIZE+IPHDR_SIZE)));

	    //checksum rampage
	    icmpptr = packet + IPHDR_SIZE+ICMPHDR_SIZE+IPHDR_SIZE ;//pkt2
	    icmpptr->checksum = htons(calc_icmp_checksum((uint16_t*)icmpptr, ICMPHDR_SIZE));

	    ipptr = packet + IPHDR_SIZE+ICMPHDR_SIZE;// ip_pkt2
	    ipptr->checksum = htons(calc_icmp_checksum((uint16_t*)ipptr, IPHDR_SIZE));

	    icmpptr = packet + IPHDR_SIZE ;//pkt
	    icmpptr->checksum = htons(calc_icmp_checksum((uint16_t*)icmpptr, ICMPHDR_SIZE));

	    ipptr = packet; 
	    ipptr->checksum = htons(calc_icmp_checksum((uint16_t*)ipptr, IPHDR_SIZE));
	    
	    /*
	     
	      ip_pkt2	= malloc(IPHDR_SIZE);
		memset(ip_pkt2, 0, IPHDR_SIZE);
		ip_pkt2->vers_ihl = 0x45;
		ip_pkt2->tos = 0;
		ip_pkt2->pkt_len = (IPHDR_SIZE + ICMPHDR_SIZE) << 8;
		ip_pkt2->id = 1; //kernel sets proper value htons(ip_id_counter);
		ip_pkt2->flags_frag_offset = 0;
		ip_pkt2->ttl = 1; // real TTL would be 1 on a time exceeded packet
		ip_pkt2->proto = 1; // ICMP
		ip_pkt2->checksum = 0; // maybe the kernel helps us out..?
		ip_pkt2->src_ip = dest_addr->sin_addr.s_addr;//htonl(0x7f000001); // localhost..
		ip_pkt2->dst_ip = src_addr->sin_addr.s_addr;//htonl(0x7f000001); // localhost..
	   
		pkt2 = malloc(ICMPHDR_SIZE);
		memset(pkt2, 0, ICMPHDR_SIZE);
		pkt2->type = 8; // ICMP echo request
		pkt2->code = 0; // Must be zero 
		pkt2->identifier = 0;
		pkt2->seq = 0;
		pkt2->checksum = 0;

		pkt2->checksum = htons(calc_icmp_checksum((uint16_t*)pkt2, ICMPHDR_SIZE));
		ip_pkt2->checksum = htons(calc_icmp_checksum((uint16_t*)ip_pkt2, IPHDR_SIZE));
		
		memcpy(packet+IPHDR_SIZE+ICMPHDR_SIZE, ip_pkt2, IPHDR_SIZE);
		memcpy(packet+IPHDR_SIZE+ICMPHDR_SIZE+IPHDR_SIZE, pkt2, ICMPHDR_SIZE);

	     */
		  

	    
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
            return 0;}

int main(int argc, char *argv[]){
  

            struct sockaddr_in src, dest;
            char *target_host;
            int icmp_sock;
            
            printf("usage: sudo ./icmp <ip4_address>\n");
            
            /* read cmd line arg */
            target_host = argv[1];
            
            /* clear src,dest structs */
            memset(&src, 0, sizeof(struct sockaddr_in));
	    memset(&dest, 0, sizeof(struct sockaddr_in));
            
            /* fill out dest struct */
            dest.sin_family        = AF_INET;
            dest.sin_port          = 0;
            inet_pton(AF_INET, target_host, &dest.sin_addr);

            /* open raw socket */
            icmp_sock = create_icmp_socket();

            /* make sure no socket errors */
            if (icmp_sock == -1) {
              printf("couldn't create icmp socket\n");
              exit(1);}
            
            // dest provided as cmdline arg, but lets override with 3.3.3.3
	    /*struct hostent *host_ent;
	    uint32_t timeexc_ip;
	    memset(&dest, 0, sizeof(struct sockaddr_in));
	    host_ent                    = gethostbyname("3.3.3.3");
	    timeexc_ip                  = *(uint32_t*)host_ent->h_addr_list[0];
	    dest.sin_family        = AF_INET;
	    dest.sin_port          = 0;
	    dest.sin_addr.s_addr   = timeexc_ip;*/
	    /* send icmp echo request */
	    //send_icmp_echorequest(icmp_sock, &src, &dest);

	    /*send icmp ttl exceeded, 3.3.3.3 baked in*/
	    send_icmp_ttlexceeded(icmp_sock, &src, &dest);

	    close(icmp_sock);
            
            printf("Sent ICMP echo-request to %s\n", target_host);
            fflush(stdout);
            return 0;

}

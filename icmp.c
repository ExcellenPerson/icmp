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

#include <sys/fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h> /* IPPROTO_RAW def. */
#include <netinet/ip.h>


#include "icmp_packet.h"
#include "ip_packet.h"

unsigned const int one = 1;

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

/* given a src and dest and open icmp socket, send echo-request */
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
            
            /* send icmp echo request */
            send_icmp_echorequest(icmp_sock, &src, &dest);
            close(icmp_sock);
            
            printf("Sent ICMP echo-request to %s\n", target_host);
            fflush(stdout);
            return 0;
}

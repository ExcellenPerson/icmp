OBJS = icmp_packet.o ip_packet.o
all : icmp

icmp : icmp.o ${OBJS}
	gcc -o icmp icmp.c ${OBJS}
ip_packet.o: ip_packet.c ip_packet.h
icmp_packet.o: icmp_packet.c icmp_packet.h

clean :
	rm icmp *.o

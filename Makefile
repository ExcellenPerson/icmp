all : icmp

icmp : icmp.o
	gcc -o icmp icmp.o 
	rm *.o

icmp.o : icmp.c
	gcc -c icmp.c

clean :
	rm icmp *.o

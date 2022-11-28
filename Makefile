# Makefile Analyseur de trame 
CC=gcc
CFLAGS= -Wall -Werror -Wextra
LIBFLAGS= -lpcap

all : proj

proj:
	$(CC) $(CFLAGS) analyseur.c fct.c -o analyseur $(LIBFLAGS)

exec_o : all 
	./analyseur o capture_trame/dhcp/dhcp_.pcap

exec_i : all
	./analyseur i

clean: 
	$(RM) analyseur
# Makefile Analyseur de trame 
CC=gcc
CFLAGS= -Wall -Werror -Wextra
LIBFLAGS= -lpcap

all : proj

proj:
	$(CC) $(CFLAGS) analyseur.c fct.c -o analyseur $(LIBFLAGS)

clean: 
	$(RM) analyseur
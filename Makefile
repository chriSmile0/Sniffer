# Makefile Analyseur de trame 
CC=gcc
CFLAGS= -Wall -Werror -Wextra
LIBFLAGS= -lpcap

all : proj

proj:
	$(CC) $(CFLAGS) analyseur.c fct.c -o analyseur $(LIBFLAGS)

exec_o : all  # choix du fichier en entrée 
	./analyseur o $(ARGS) 

exec_i : all
	./analyseur i 

clean: 
	$(RM) analyseur
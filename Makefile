# Makefile Analyseur de trame 
CC=gcc
CFLAGS= -Wall -Werror -Wextra
LIBFLAGS= -lpcap

all : proj

proj:
	$(CC) $(CFLAGS) analyseur.c fct.c -o analyseur $(LIBFLAGS)

exec_o : all  # choix du fichier en entrée 
	./analyseur -o $(ARGS) -v 3  

exec_i : all
	./analyseur -i $(ARGS) -v 3 

exec_i_filter : all 
	./analyseur -i $(ARGS1) -v 3 -f $(ARGS2)
#Note pour un filtrage composé comme 'port 23' par exemple, le mieux est de faire : 
# ARGS2="port\ 23" dans la ligne de commande
 
clean: 
	$(RM) analyseur
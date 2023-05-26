# Makefile Analyseur de trame 
### Commentaires d'utilisations
# Vous trouverez si dessous un Makefile qui vous permettrez 
# 2 choses : 
# 	1 -> Compilé le projet et le tester avec une ligne de commande complète
# 
#
# 	2 -> L'éxécuté via 3 cible précise : 
#		_o -> Entrée du fichier et de la version requise via 
#			make exec_o FILE=<FICHIER> V={1|2|3}
#
#		_i -> Entrée de l'interface et de la version requise via
#			make exec_i INTER=<INTERFACE> V={1|2|3}
#
#		_i_filter -> Entrée de l'interface , de la version et du filtre via
#			make exec_i INTER=<INTERFACE> V={1|2|3} FILTRE=<FILTRE>
#	
### Fin commentaires d'utilisations

CC=gcc
CFLAGS= -Wall -Werror -Wextra
LIBFLAGS= -lpcap
SRC = "src/"
INC = "inc/"

all : proj

proj:
	$(CC) $(CFLAGS) analyseur.c $(SRC)*.c -o analyseur $(LIBFLAGS)

exec_o : all  # choix du fichier en entrée 
	./analyseur -o $(FILE) -v $(V)   

exec_i : all
	./analyseur -i $(INTER) -v $(V)

exec_i_filter : all 
	./analyseur -i $(INTER) -v $(V) -f $(FILTRE)
#Note pour un filtrage composé comme 'port 23' par exemple, 
#le mieux est de faire : FILTRE="port\ 23" dans la ligne de commande
 
clean: 
	$(RM) analyseur
#ifndef TCP_INC_H
#define TCP_INC_H
#include "utile.h"
#include "netinet/tcp.h"
#include "arpa/telnet.h"


/**
 * @version 1.0
 * 
 * @brief	Affiche de manière lisible,précise et dans l'ordre logique 
 * 			les champs importants d'un en-tête TCP
 * 
 * @param[:tcp] une structure tcp_hdr qui est un ensemble de champs short/long
 * 			afin de pouvoir lire le contenu de la trame
 * 
 * @return noreturn 
*/

void print_tcp_header(const struct tcphdr *tcp, int verbose);

/**
 * @version 1.0
 * 
 * @brief	Permet d'afficher de manière similaire a tcpdump les
 * 			options de l'entête tcp  
 * 
 * @param[:nb_options] le nombre d'options de tcp 
 * @param[:index_trame] index du début des options tcp 
 * @param[:verbose] le niveau de verbosité 
 * @param[:paquet] le paquet qui correspond au début des options tcp 
 * 
 * @return noreturn 
*/

void print_tcp_options(int nb_options,int index_trame, int verbose,
	const u_char *paquet);

void print_telnet(const u_char *paquet, int index_trame);

#endif // TCP_INC 
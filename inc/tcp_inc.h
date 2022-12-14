#ifndef TCP_INC_H
#define TCP_INC_H
#include "utile.h"
#include "netinet/tcp.h"


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



void print_tcp_options(int nb_options,int index_trame, int verbose,
    const u_char *paquet);

#endif // TCP_INC 
#ifndef UTILE_H
#define UTILE_H
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @version 1.0
 * 
 * @brief	Affiche sur la sortie l'adresse de destination(1>) ou de source(0)
 * 			de manière lisible pour un utilisateur (V1.0 = v4)
 * 
 * @param[:ip_addr] une structure ip_addr qui contient une structure s_addr
 * @param[:src_or_dst] choix entre 0 pour src et 1> pour dst 
 * 
 * @return noreturn
*/

void print_addr(struct in_addr ip_addr, int src_or_dst); // print addr to format #.#.#.#. or 1:1:1:1:1:1:

#endif // UTILE_H
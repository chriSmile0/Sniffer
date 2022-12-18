#ifndef ETHER_INC_H
#define ETHER_INC_H
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>



/**
 * @version 1.0
 * 
 * @brief	Permet d'afficher de manière claire les champs 
 * 			de l'entête ethernet d'une trame du même nom
 * 
 * @param[:ether] une structure ether_header qui permet de recueillir le type 
 * 					de données (IP4/6,etcc) et les adresses MAC src et dst
 * @param[:verbose] le niveau de verbosité 
 *
 * @return noreturn 
*/

void print_ethernet_header(const struct ether_header *ether, int verbose);

#endif // ETHER_INC_H
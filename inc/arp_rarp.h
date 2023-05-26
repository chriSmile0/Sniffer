#ifndef ARP_RARP_INC_H
#define ARP_RARP_INC_H
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include "utile.h"



/**
 * @version 1.0
 * 
 * @brief	Permet d'affiché de manière claire les champs d'un entête
 * 			ARR/RARP 
 * 
 * @param[:arp] une structure ether_arp qui contient les champs associés
 * @param[:verbose] le niveau de verbosité
 * 
 * @return noreturn
*/

void print_arp_header(const struct ether_arp *arp, int verbose);

#endif // ARP_RARP_INC_H
#ifndef IP_INC_H
#define IP_INC_H
#include "headers.h"
#include "bootp.h"
#include "utile.h"

/**
 * @version 1.0
 * 
 * @brief	Affiche de manière lisible,précise et dans l'ordre logique
 * 			les champs importans d'un en-tête IP
 * 
 * @param[:ip] une structure ip_hdr qui est un ensemble de char/short 
 * 				afin de pouvoir lire le contenu de la trame
 * 
 * @return noreturn
*/

void print_ip_header(const struct ip* ip, int verbose);

/**
 * @version 1.0
 * 
 * @brief	Affiche de manière lisible,précise et dans l'ordre logique 
 * 			les champs importants d'un en-tête UDP
 * 
 * @param[:udp] une structure udp_hdr qui est un ensemble de champs char 
 * 			afin de pouvoir lire le contenu de la trame
 * 
 * @return noreturn
*/

void print_udp_header(const struct udphdr * udp, int verbose);



/**
 * @version 1.0
 * 
 * @brief	Affiche de manière lisible,précise et dans l'ordre logique
 * 			les champs importants d'un en-tête ARP
 * 
 * @param[:arp] une structure arp_hdr qui est un ensemble de champs char
 * 			/short/long afin de pouvoir lire le contenu de la trame
 * 
 * @return noreturn
*/

void print_bootp_header(struct bootp *b_p, int verbose);

/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/


char * trad_msg_type_dhcp(int valeur);

void dhcp_tlv(int type,int *tab_val, int taille_tab);

void print_dns_header(const HEADER *dns);

#endif // IP_INC_H 
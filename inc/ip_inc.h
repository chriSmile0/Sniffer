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
 * @param[:verbose] niveau de verbosité 
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
 * @param[:verbose] niveau de verbosité 
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
 * @param[:b_p] une structure arp_hdr qui est un ensemble de champs char
 * 			/short/long afin de pouvoir lire le contenu de la trame
 * @param[:verbose] niveau de verbosité 
 * 
 * @return noreturn
*/

void print_bootp_header(struct bootp *b_p, int verbose);

/**
 * @version 1.0
 * 
 * @brief	Permet de traduire un entier en un type de requête dhcp
 * 			en chaîne de caractères
 * 
 * @param[:valeur] valeure entière du type dhcp
 * 
 * @return une chaîne de caractères correspondant au paramètre
*/


char * trad_msg_type_dhcp(int valeur);

/**
 * @version 1.0
 * 
 * @brief	Permet d'afficher de manière claire tout type d'options 
 * 			et de type de message dhcp via le décodage préalable du type
 * 			de message dhcp et donc affichage du contenu de V du TLV
 * 
 * @param[:type] type des messages dans le tlv
 * @param[:tab_val] le tableau de valeurs V
 * @param[:taille_tabl] taille du tableau de valeurs
 * 
 * @return 
*/

void dhcp_tlv(int type,int *tab_val, int taille_tab);

/**
 * @version 1.0
 * 
 * @brief	Affiche de manière lisible,précise et dans l'ordre logique 
 * 			les champs importants d'un en-tête DNS
 * 
 * @param[:dns] une structure HEADER qui est un ensemble de champs
 * 			afin de pouvoir lire le contenu de la trame
 * 
 * @return noreturn
*/


void print_dns_header(const HEADER *dns);

#endif // IP_INC_H 
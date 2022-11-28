#ifndef FCT_H
#define FCT_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "lib_net.h"
#include "lib_netinet.h"
#include "headers.h"
#include "bootp.h"

#define SIZE_OPTION 1024


struct cmd_options {
    char cmd;
    char options[SIZE_OPTION];
};

struct list_cmd_options {
    struct cmd_options *tab_options;
};


/**
 * @version 1.0
 * 
 * @brief	Parse la ligne de commande de tel sorte que toutes les options
 *			Soient utilisables et lance une erreur si la commande n'est pas 
 *			valide ou qu'il y'a erreur sur les options (<interface>)(<fichier>)
 * 
 * @param[:argc] le nombre d'arguments sur la ligne de commande
 * @param[:argv] les arguments sur la ligne de commande 
 * 
 * @return une structure qui contient la commande voulu et ses options
 * 			// Attention possibilité de faire plusieurs commandes sur la 
 * 			// même ligne 
*/

struct cmd_options parse_cmd(int argc, char **argv);

/**
 * @version 1.0
 * 
 * @brief	Permet de traîter un fichier de type tcpdump -w et de l'afficher
 * 			de manière convenable et lisible sur la sortie 
 * 
 * @param[:file] le fichier que l'on veut analyser
 * 
 * @return //Pour le moment rien
*/

void analyse_offline(char *file);

/**
 * @version 1.0
 * 
 * @brief	Lis pendant un temps indeterminé les trames qui passent sur
 * 			l'interface entrer en parametre 
 * 
 * @param[:inter] l'interface entrée sur la ligne de commande
 * 
 * @return noreturn 
*/

/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);

void analyse_online(pcap_if_t *interface);

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

void print_ip_header(const struct ip* ip);

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

void print_udp_header(const struct udphdr * udp);

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

void print_tcp_header(const struct tcphdr *tcp);

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

/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

void print_mac_adr(unsigned long long mac_adr, int src_or_dst);

/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

void print_arp_header(const struct ether_arp *arp);

/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

#endif /* FCT_H */
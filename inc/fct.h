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
#include "bootp.h"

#define SIZE_OPTION 1024

#define EDT_IP 0x0800
#define EDT_IP6 0x86DD
#define EDT_ARP 0x0806
#define EDT_RARP 0x0835

typedef struct {
	int verbose;
} arguments;

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

void analyse_offline(char *file, int verbose);

/**
 * @version 1.0
 * 
 * @brief	Lis pendant un temps indeterminé les trames qui passent sur
 * 			l'interface entrer en parametre 
 * 
 * @param[:inter] l'interface entrée sur la ligne de commande
 * @param[:filtre] le filtre potentiel que l'on utilise
 * @param[:net]
 * @param[:verbose] le niveau de verbosité 
 * @return noreturn 
*/

void analyse_online(pcap_t *handle,char *filtre, bpf_u_int32 net, int verbose);

/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:args[]] les arguments , ici juste la verbosité
 * @param[:header] le header du paquet (inutilisé)
 * @param[:paquer] le paquet à parcourir 
 * @return 
*/

void got_packet(arguments args[], const struct pcap_pkthdr *header, const u_char *paquet);

#endif /* FCT_H */
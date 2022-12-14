#include "../inc/arp_rarp.h"

void print_arp_header(const struct ether_arp *arp, int verbose)
{
	if(verbose == 1) {
		printf(" *A HDR:*: MacSrc-MacDest:%s-%s \n",
					ether_ntoa((struct ether_addr*)arp->arp_sha),
					ether_ntoa((struct ether_addr*)arp->arp_tha));
	}
	else if(verbose == 2) {
		printf("\n\t**ARP HEADER** : ");
		printf("H type: %u  ",ntohs((arp->ea_hdr).ar_hrd));
		printf("Prot: %u ",ntohs((arp->ea_hdr).ar_pro));
		printf("Op: %u ",ntohs((arp->ea_hdr).ar_op));	
		printf("@Mac src: %s  ",ether_ntoa((struct ether_addr*)arp->arp_sha));
		char buffer[INET_ADDRSTRLEN];
		inet_ntop( AF_INET, &arp->arp_spa, buffer, sizeof( buffer ));
		printf("@IP src: %s ",buffer);
		printf("@Mac dst: %s  ",ether_ntoa((struct ether_addr*)arp->arp_tha));
		inet_ntop( AF_INET, &arp->arp_tpa, buffer, sizeof( buffer ));
		printf("@IP dst: %s \n",buffer);
	}
	else {
		printf("\n\t**ARP HEADER**\n");
		printf("Hardware type : %u\n",ntohs((arp->ea_hdr).ar_hrd));
		printf("Protocole : %u\n",ntohs((arp->ea_hdr).ar_pro));
		printf("Type d'adresse physique %u\n",(arp->ea_hdr).ar_hln);
		printf("Taille du type de protocole : %u\n",(arp->ea_hdr).ar_pln);
		printf("Operation : %u\n",ntohs((arp->ea_hdr).ar_op));
		printf("Adresse Mac source : %s\n",ether_ntoa((struct ether_addr*)arp->arp_sha));
		char buffer[INET_ADDRSTRLEN];
		inet_ntop( AF_INET, &arp->arp_spa, buffer, sizeof( buffer ));
		printf("IP adresse source : %s ",buffer);
		inet_ntop( AF_INET, &arp->arp_tpa, buffer, sizeof( buffer ));
		printf("IP adresse destination : %s \n",buffer);
	}
}
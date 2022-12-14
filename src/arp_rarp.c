#include "../inc/arp_rarp.h"

void print_arp_header(const struct ether_arp *arp)
{
	printf("**ARP HEADER**\n");
	printf("Hardware type : %u\n",ntohs((arp->ea_hdr).ar_hrd));
	printf("Protocole : %u\n",ntohs((arp->ea_hdr).ar_pro));
	printf("Type d'adresse physique %u\n",(arp->ea_hdr).ar_hln);
	printf("Taille du type de protocole : %u\n",(arp->ea_hdr).ar_pln);
	printf("Operation : %u\n",ntohs((arp->ea_hdr).ar_op));
	printf("Adresse Mac source : %s\n",ether_ntoa((struct ether_addr*)arp->arp_sha));
	struct in_addr *add;
	add = malloc(sizeof(struct in_addr));
	inet_aton((char*)arp->arp_spa,add);
	printf("IP adresse source : %s\n",inet_ntoa(*add));
	printf("Adresse Mac destination : %s\n",ether_ntoa((struct ether_addr*)arp->arp_tha));
	struct in_addr *add2;
	add2 = malloc(sizeof(struct in_addr));
	inet_aton((char*)arp->arp_tpa,add2);
	printf("IP Adresse destination : %s\n",inet_ntoa(*add2));
	
	(void) arp;
}
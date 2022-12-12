#include "../inc/arp_rarp.h"

void print_arp_header(const struct ether_arp *arp)
{
	printf("**ARP HEADER**\n");
	printf("Hardware type : %u\n",(arp->ea_hdr).ar_hrd);
	printf("Protocole : %u\n",(arp->ea_hdr).ar_pro);
	printf("Type d'adresse physique %u\n",(arp->ea_hdr).ar_hln);
	printf("Taille du type de protocole : %u\n",(arp->ea_hdr).ar_pln);
	printf("Operation : %u\n",(arp->ea_hdr).ar_op);
	printf("Adresse Mac source : %s\n",ether_ntoa((struct ether_addr*)arp->arp_sha));
	(void) arp;
}
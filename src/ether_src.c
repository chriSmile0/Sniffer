#include "../inc/ether_inc.h"

#define EDT_IP 0x0800
#define EDT_IP6 0x86DD
#define EDT_ARP 0x0806
#define EDT_RARP 0x0835

void print_ethernet_header(const struct ether_header *ether)
{
	printf("**ETHERNET HEADER**\n");
    printf("%s\n",ether_ntoa((struct ether_addr*)ether->ether_shost));
    printf("%s\n",ether_ntoa((struct ether_addr*)ether->ether_dhost));
    int type_EDT = ntohs(ether->ether_type);
    switch(type_EDT) {
        case EDT_IP6:
            printf("Type :(%x) IPV6\n",EDT_IP6);
            break;
        case EDT_IP:
            printf("Type :(%x) IPV4\n",EDT_IP);
            break;
        case EDT_ARP:
			printf("Type :(%x) ARP\n",EDT_ARP);
            break;
        case EDT_RARP:
			printf("Type :(%x) RARP\n",EDT_RARP);
            break;
		default:
			break;
    }  
}
#include "../inc/ether_inc.h"

#define EDT_IP 0x0800
#define EDT_IP6 0x86DD
#define EDT_ARP 0x0806
#define EDT_RARP 0x0835

void print_ethernet_header(const struct ether_header *ether, int verbose)
{
    char space_or_backline = (verbose == 3) ? '\n' : ' ';
    if(verbose == 1 || verbose == 2)
        printf("**E_HDR** :");
    else 
	    printf("**ETHERNET HEADER** \n");
    
    printf("@MacSrc:%s %c",ether_ntoa((struct ether_addr*)ether->ether_shost),
        space_or_backline);
    printf("@MacDst:%s %c" ,ether_ntoa((struct ether_addr*)ether->ether_dhost),
        space_or_backline);
    int type_EDT = ntohs(ether->ether_type);
    switch(type_EDT) {
        case EDT_IP6:
            if(space_or_backline == ' ')
                printf("T IPV6");
            else
                printf("Type :(%x) IPV6\n",EDT_IP6);
            break;
        case EDT_IP:
            if(space_or_backline == ' ')
                printf("T IPV4 ");
            else
            printf("Type :(%x) IPV4\n",EDT_IP);
            break;
        case EDT_ARP:
            if(space_or_backline == ' ')
                printf("T ARP ");
            else
			printf("Type :(%x) ARP\n",EDT_ARP);
            break;
        case EDT_RARP:
            if(space_or_backline == ' ')
                printf("T RARP ");
            else
			printf("Type :(%x) RARP\n",EDT_RARP);
            break;
		default:
			break;
    }  
}
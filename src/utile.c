#include "../inc/utile.h"

void print_addr(struct in_addr ip_addr, int src_or_dst) //0 for src , 1 for dst
{
	char buffer[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &ip_addr, buffer, sizeof( buffer ));
	char *message = (!src_or_dst) ? "source": "destination";
	printf( "adresse %s :%s\n", message,buffer );  
}
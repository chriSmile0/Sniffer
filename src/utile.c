#include "../inc/utile.h"

void print_addr(struct in_addr ip_addr, int src_or_dst) //0 for src , 1 for dst
{
	char buffer[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &ip_addr, buffer, sizeof( buffer ));
	char *message = (!src_or_dst) ? "source": "destination";
	printf( "adresse %s :%s\n", message,buffer );  
}


void print_mac_adr(unsigned long long mac_adr, int src_or_dst)
{
	(void) src_or_dst;
	(void) mac_adr;

}


struct in_addr* cast_uint32_in_in_addr(u_int32_t value) 
{
	struct in_addr *s_a;
	s_a = malloc(sizeof(struct in_addr));
	s_a->s_addr = value;
	(void) s_a;
	return s_a;
}

struct in_addr* cast_uint8_in_in_addr(const u_int8_t* val) 
{
	struct in_addr *s_a;
	s_a = malloc(sizeof(struct in_addr));
	s_a->s_addr = (in_addr_t)*val;
	(void) s_a;
	return s_a;
}

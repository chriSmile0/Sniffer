#include "../inc/ip_inc.h"

void print_ip_header(const struct ip * ip, int verbose)
{
	char buffer1[INET_ADDRSTRLEN];
	char buffer2[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &ip->ip_src, buffer1, sizeof( buffer1 ));
	//printf("@IP src: %s ",buffer);
	inet_ntop( AF_INET, &ip->ip_dst, buffer2, sizeof( buffer2 ));
	//printf("@IP dst: %s ",buffer);
	char *prot = (ip->ip_p == 6) ? "TCP" : "UDP";

	if(verbose == 1) {
		printf(" *IP4:* Src-Dst:%s-%s Prot: %s ",buffer1,buffer2,prot);
	}
	else if(verbose == 2) {
		printf("\n\t**IP HEADER** : Prot: %s Len: %u ",prot,ntohs(ip->ip_len));
		printf("Id: %u Checksum: %x ",ntohs(ip->ip_id),ip->ip_sum);
		printf("@Src: %s @Dst: %s ",buffer1,buffer2);
	}
	else {
		printf("\n\t**IP HEADER**\n");
		printf("Version : %u\n",ip->ip_v);
		printf("IHL : %u\n",ip->ip_hl);
		printf("ip tos : %d\n",ip->ip_tos);
		printf("ip taille : %u\n",ntohs(ip->ip_len));
		printf("Id : %u\n",ntohs(ip->ip_id));
		printf("Offset : %u\n",ip->ip_off);
		printf("Time to live : %u\n",ip->ip_ttl);
		printf("Prot : %s\n",prot); 
		printf("Checksum : %u\n",ip->ip_sum);
		print_addr((ip->ip_src),0);
		print_addr((ip->ip_dst),1); 
	}
}

void print_udp_header(const struct udphdr * udp, int verbose)
{
	unsigned short s = ntohs(udp->source);
	unsigned short d = ntohs(udp->dest);
	unsigned short t = ntohs(udp->len);
	unsigned short c = udp->check;
	if(verbose == 1) {
		printf(" *UDP:* s-d:%u-%u len: %u",s,d,t);
	}
	else if(verbose == 2) {
		printf("\n\t\t**UDP HEADER** : Psrc: %u Pdst: %u Len: %u Check: %x",
			s,d,t,c);
	}
	else {
		printf("**UDP HEADER**\n");
		printf("Port Source : %u\n",s);
		printf("Port Destination : %u\n",d);
		printf("Taille : %u\n",t);
		printf("Checksum : %x\n",c);
	}
}

void print_bootp_header(struct bootp *b_p, int verbose) 
{

	char *t_op = (b_p->bp_op == 1) ? "Request" : "Reply";
	u_int8_t ht = b_p->bp_htype;
	u_int8_t hl = b_p->bp_hlen;
	u_int8_t ho = b_p->bp_hops;
	u_int32_t xid = b_p->bp_xid;
	u_int16_t flgs = b_p->bp_flags;
	char * mac_c = ether_ntoa((struct ether_addr*)b_p->bp_chaddr);
	char *serverhostname = ether_ntoa((struct ether_addr*)b_p->bp_sname);
	char *value_flgs = (flgs == 0) ? "Unicast" : (flgs == 0x800) ? "Broadcast" : "Autre";
	char buffer[INET_ADDRSTRLEN];
	char buffer2[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &b_p->bp_ciaddr, buffer, sizeof( buffer ));
	inet_ntop( AF_INET, &b_p->bp_siaddr, buffer2, sizeof( buffer2 ));
	char *dhcp = NULL;
	if((b_p->bp_vend[0] == 99 && (b_p->bp_vend[1] == 130) 
			&& (b_p->bp_vend[2]== 83) && (b_p->bp_vend[3] == 99)))
		dhcp = "DHCP";
	
	if(verbose == 1) {
		printf(" *BP:* o:%s cadr:%s sadr:%s %s",t_op,buffer,buffer2,dhcp);
	}
	else if(verbose == 2) {
		printf("\n\t\t\t**BOOTP HEADER : op: %s ht-hl:%d-%d flgs: %s xid: %x",
			t_op,ht,hl,value_flgs,ntohl(xid));
		printf(" @MacClient: %s %s",mac_c,dhcp);
	}
	else {
		printf("**BOOTP HEADER**\n");
		printf("op : %s\n",t_op);			
		printf("htype : %u\n",ht);	
		printf("hlen : %u\n",hl);	
		printf("hops : %u\n",ho);	
		printf("xid: %x\n",ntohl(xid));		
		printf("secs : %u\n",b_p->bp_secs);	
		printf("flags : %x\n",ntohs(b_p->bp_flags));
		print_addr(b_p->bp_ciaddr,0); 
		print_addr(b_p->bp_yiaddr,1); 
		print_addr(b_p->bp_siaddr,0); 
		print_addr(b_p->bp_giaddr,1);
		printf("Client mac adresse %s\n",mac_c);
		printf("server host name padding %s\n",serverhostname);
	}

	printf("\nDHCP messages\n");
	int stop = 1;
	int i = 4;
	while(stop) 
	{
		int taille_valeurs = 0;
		if((b_p->bp_vend[i] == 255) || (b_p->bp_vend[i] == 0))
			stop = 0;
		printf("Option(%d): \n",b_p->bp_vend[i]);
		taille_valeurs = b_p->bp_vend[i+1];
		printf("Length : %d\n",taille_valeurs);
		int *tab_val;
		tab_val = calloc(taille_valeurs,4); 
		for(int j = 0 ; j < taille_valeurs; j++) 
			tab_val[j] = b_p->bp_vend[j+i+2];
		dhcp_tlv(b_p->bp_vend[i],tab_val,taille_valeurs);
		i += taille_valeurs+2;
	}
	(void) stop;
	
}


char * trad_msg_type_dhcp(int valeur)
{
	switch(valeur) 
	{
		case 1 : 
			return "discover";
			break;
		case 2 : 
			return "offer";
			break;
		case 3 : 
			return "request";
			break;
		case 6 : 
			return "ack";
			break;
		case 7 :
			return "release"; 
			break;
		default: 
			return "None";
			break;
	}
}

void dhcp_tlv(int type,int *tab_val, int taille_tab) 
{
	(void) taille_tab;
	if(type < 10)
	{
		if((type == 1) || (type == 3) || (type == 6))
			for(int i = 0 ; i < taille_tab; i++) 
			{
				if(i%4 == 0)
					printf(",");
				printf("%d.",tab_val[i]);
			}
		else 
			printf("%d",tab_val[0]);	
	}
	else if(type < 20) 
	{
		for(int i = 0 ; i < taille_tab; i++) 
			printf("%c",tab_val[i]);
	}
	else if(type < 50)
	{
		for(int i = 0 ; i < taille_tab; i++) 
			printf("%d.",tab_val[i]);
	}
	else {
		if((type == 50) || (type == 55) ||(type == 61) ||(type == 54))
			for(int i = 0 ; i < taille_tab; i++) 
				printf("%d.",tab_val[i]);
		else if(type == 53)
			printf("DHCP Message type : (%d) : %s",
				tab_val[0],trad_msg_type_dhcp(tab_val[0]));
		else if(type == 51)
			printf("%d",tab_val[0]);
	}
	printf("\n\n");
}






void print_dns_header(const HEADER *dns) 
{
	printf("**DNS HEADER**\n");
	printf("requête id : %x\n",ntohs(dns->id)); 		/*%< query identification number */
							
	printf("Recursion desirer : %d\n",dns->rd);		/*%< recursion desired */
	printf("message tronquer : %d\n",dns->tc); 		/*%< truncated message */
	printf("Message de l'autorité : %d\n",dns->aa); 		/*%< authoritive answer */
	printf("Objectif : %d\n",dns->opcode);	/*%< purpose of message */
	printf("Flags réponse : %d\n",dns->qr); 		/*%< response flag */
			/* fields in fourth byte */
	printf("Code réponse : %d\n",dns->rcode);	/*%< response code */
	printf("Check de désactivation par résolution : %d\n",dns->cd);		/*%< checking disabled by resolver */
	printf("Data authentique par nom : %d\n",dns->ad);/*%< authentic data from named */
	printf("Inutilisé : %d\n",dns->unused);					/*%< unused bits (MBZ as of 4.9.3a3) */
	printf("Récursion disponible : %d\n",dns->ra);		/*%< recursion available */

	printf("Questions : %u\n",ntohs(dns->qdcount));	/*%< number of question entries */
	printf("Réponses  : %u\n",ntohs(dns->ancount));	/*%< number of answer entries */
	printf("Entrées de l'autorité : %u\n",ntohs(dns->nscount));	/*%< number of authority entries */
	printf("Entrées ressources : %u\n",ntohs(dns->arcount));	/*%< number of resource entries */
}
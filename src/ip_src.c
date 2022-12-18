#include "../inc/ip_inc.h"

void print_ip_header(const struct ip * ip, int verbose)
{
	char buffer1[INET_ADDRSTRLEN];
	char buffer2[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &ip->ip_src, buffer1, sizeof( buffer1 ));
	inet_ntop( AF_INET, &ip->ip_dst, buffer2, sizeof( buffer2 ));
	char *prot = (ip->ip_p == 6) ? "TCP" : "UDP";

	if(verbose == 1) 
	{
		printf(" *IP4:* Src-Dst:%s-%s Prot: %s ",buffer1,buffer2,prot);
	}
	else if(verbose == 2) 
	{
		printf("\n\t**IP HEADER** : Prot: %s Len: %u ",prot,ntohs(ip->ip_len));
		printf("Id: %u Checksum: %x ",ntohs(ip->ip_id),ip->ip_sum);
		printf("@Src: %s @Dst: %s ",buffer1,buffer2);
	}
	else 
	{
		printf("\t**IP HEADER**\n");
		printf("\tVersion : %u\n",ip->ip_v);
		printf("\tIHL : %u\n",ip->ip_hl);
		printf("\tip tos : %d\n",ip->ip_tos);
		printf("\tip taille : %u\n",ntohs(ip->ip_len));
		printf("\tId : %u\n",ntohs(ip->ip_id));
		printf("\tOffset : %u\n",ip->ip_off);
		printf("\tTime to live : %u\n",ip->ip_ttl);
		printf("\tProt : %s\n",prot); 
		printf("\tChecksum : %u\n",ip->ip_sum);
		printf("\t@Src: %s \n",buffer1);
		printf("\t@Dst: %s \n",buffer2);
	}
}

void print_udp_header(const struct udphdr * udp, int verbose)
{
	unsigned short s = ntohs(udp->source);
	unsigned short d = ntohs(udp->dest);
	unsigned short t = ntohs(udp->len);
	unsigned short c = udp->check;
	if(verbose == 1) 
	{
		printf(" *UDP:* s-d:%u-%u len: %u",s,d,t);
	}
	else if(verbose == 2) 
	{
		printf("\n\t\t**UDP HEADER** : Psrc: %u Pdst: %u Len: %u Check: %x",
			s,d,t,c);
	}
	else 
	{
		printf("\t\t**UDP HEADER**\n");
		printf("\t\tPort Source : %u\n",s);
		printf("\t\tPort Destination : %u\n",d);
		printf("\t\tTaille : %u\n",t);
		printf("\t\tChecksum : %x\n",c);
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
	char *serverhostname = ether_ntoa((struct ether_addr*)b_p->bp_sname);
	char *value_flgs = (flgs == 0) ? "Unicast" : (flgs == 0x800) ? "Broadcast" : "Autre";
	char buffer[INET_ADDRSTRLEN];
	char buffer2[INET_ADDRSTRLEN];
	char buffer3[INET_ADDRSTRLEN];
	char buffer4[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &b_p->bp_ciaddr, buffer, sizeof( buffer ));
	inet_ntop( AF_INET, &b_p->bp_siaddr, buffer2, sizeof( buffer2 ));
	inet_ntop( AF_INET, &b_p->bp_yiaddr, buffer3, sizeof( buffer3 ));
	inet_ntop( AF_INET, &b_p->bp_giaddr, buffer4, sizeof( buffer4 ));
	char *dhcp = NULL;
	if((b_p->bp_vend[0] == 99 && (b_p->bp_vend[1] == 130) 
			&& (b_p->bp_vend[2]== 83) && (b_p->bp_vend[3] == 99)))
		dhcp = "DHCP";
	
	if(verbose == 1) 
	{
		printf(" *BP:* o:%s cadr:%s sadr:%s %s",t_op,buffer,buffer2,dhcp);
	}
	else if(verbose == 2) 
	{
		printf("\n\t\t\t**BOOTP HEADER : op: %s ht-hl:%d-%d flgs: %s xid: %x",
			t_op,ht,hl,value_flgs,ntohl(xid));
		printf(" @MacClient: %s %s",
			ether_ntoa((struct ether_addr*)b_p->bp_chaddr),dhcp);
	}
	else 
	{
		printf("\t\t\t**BOOTP HEADER**\n");
		printf("\t\t\top : %s\n",t_op);			
		printf("\t\t\thtype : %u\n",ht);	
		printf("\t\t\thlen : %u\n",hl);	
		printf("\t\t\thops : %u\n",ho);	
		printf("\t\t\txid: %x\n",ntohl(xid));		
		printf("\t\t\tsecs : %u\n",b_p->bp_secs);	
		printf("\t\t\tflags : %x\n",ntohs(b_p->bp_flags));
		printf("\t\t\tClient addr :  %s\n",buffer);
		printf("\t\t\tServer addr :  %s\n",buffer2);
		printf("\t\t\tSource addr :  %s\n",buffer3);
		printf("\t\t\tGateway addr :  %s\n",buffer4);
		printf("\t\t\tClient mac adresse %s\n",ether_ntoa((struct ether_addr*)b_p->bp_chaddr));
		printf("\t\t\tserver host name padding %s",serverhostname);
	}

	printf("\n\t\t\t\t**DHCP messages**\n");
	int stop = 1;
	int i = 4;
	while(stop) 
	{
		int taille_valeurs = 0;
		if((b_p->bp_vend[i] == 255) || (b_p->bp_vend[i] == 0))
			stop = 0;
		printf("\t\t\t\tOption(%d): \n",b_p->bp_vend[i]);
		taille_valeurs = b_p->bp_vend[i+1];
		printf("\t\t\t\tLength : %d\n",taille_valeurs);
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
	printf("\t\t\t\t");
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
	else 
	{
		if((type == 50) || (type == 55) ||(type == 61) || (type == 54))
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
	printf("\n\t\t\t**DNS HEADER**\n");
	printf("\t\t\trequête id : %x\n",ntohs(dns->id)); 							
	printf("\t\t\tRecursion desirer : %d\n",dns->rd);		
	printf("\t\t\tmessage tronquer : %d\n",dns->tc); 		
	printf("\t\t\tMessage de l'autorité : %d\n",dns->aa); 		
	printf("\t\t\tObjectif : %d\n",dns->opcode);
	printf("\t\t\tFlags réponse : %d\n",dns->qr); 		
	printf("\t\t\tCode réponse : %d\n",dns->rcode);	
	printf("\t\t\tCheck de désactivation par résolution : %d\n",dns->cd);		
	printf("\t\t\tData authentique par nom : %d\n",dns->ad);
	printf("\t\t\tInutilisé : %d\n",dns->unused);					
	printf("\t\t\tRécursion disponible : %d\n",dns->ra);	
	printf("\t\t\tQuestions : %u\n",ntohs(dns->qdcount));
	printf("\t\t\tRéponses  : %u\n",ntohs(dns->ancount));
	printf("\t\t\tEntrées de l'autorité : %u\n",ntohs(dns->nscount));
	printf("\t\t\tEntrées ressources : %u\n",ntohs(dns->arcount));
}
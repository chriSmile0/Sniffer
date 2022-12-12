#include "../inc/ip_inc.h"

void print_ip_header(const struct ip * ip)
{
	printf("**IP HEADER**\n");
	printf("Version : %u\n",ip->ip_v);
	printf("IHL : %u\n",ip->ip_hl);

	printf("ip tos : %d\n",ip->ip_tos);
	printf("ip taille : %u\n",ntohs(ip->ip_len));
	printf("Id : %u\n",ntohs(ip->ip_id));
	printf("Offset : %u\n",ip->ip_off);
	printf("time to live : %u\n",ip->ip_ttl);
	printf("prot : %u\n",ip->ip_p);//good 
	printf("Checksum : %u\n",ip->ip_sum);
	print_addr((ip->ip_src),0);
	print_addr((ip->ip_dst),1); 
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

void print_bootp_header(struct bootp *b_p) 
{
	printf("**BOOTP HEADER**\n");
	printf("op : %u\n",b_p->bp_op);			/* packet opcode type */
	printf("htype : %u\n",b_p->bp_htype);	/* hardware addr type */
	printf("hlen : %u\n",b_p->bp_hlen);	/* hardware addr length */
	printf("hops : %u\n",b_p->bp_hops);	/* gateway hops */
	printf("xid: %u\n",b_p->bp_xid);		/* transaction ID */
	printf("secs : %u\n",b_p->bp_secs);	/* seconds since boot began */
	printf("flags : %u\n",b_p->bp_flags);	/* flags: 0x8000 is broadcast */
	
	print_addr(b_p->bp_ciaddr,0); // client IP address 
	print_addr(b_p->bp_yiaddr,1); // 'your' IP address 
	print_addr(b_p->bp_siaddr,0); // server IP address 
	print_addr(b_p->bp_giaddr,1); // gateway IP address 

	printf("Client mac adresse %s\n",ether_ntoa((struct ether_addr*)b_p->bp_chaddr));
	printf("server host name padding %s\n",ether_ntoa((struct ether_addr*)b_p->bp_sname));	// server host name 
	if((b_p->bp_vend[0] == 99 && (b_p->bp_vend[1] == 130) 
			&& (b_p->bp_vend[2]== 83) && (b_p->bp_vend[3] == 99)))
		printf("MAGIC COOKIE IS PRESENT : DHCP\n");
	printf("DHCP messages\n");
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



void print_tcp_header(const struct tcphdr *tcp)
{
	printf("**TCP HEADER**\n");
	printf("Port Source : %u\n",ntohs(tcp->source));
	printf("Port Destination : %u\n",ntohs(tcp->dest));
	printf("Sequence number : %x\n",ntohs(tcp->seq));
	printf("Acknowledgment number : %x\n",ntohs(tcp->ack_seq));
	printf("Res1 : %u\n",tcp->res1);
	printf("Off : %u\n",tcp->doff);
	printf("Fin : %u\n",tcp->fin);
	printf("Syn : %u\n",tcp->syn);
	printf("Rst :%u\n",tcp->rst);
	printf("Psh :%u\n",tcp->psh);
	printf("Ack :%u\n",tcp->ack);
	printf("Urg :%u\n",tcp->urg);
	printf("Res2 :%u\n",tcp->res2);
	printf("Window : %u\n",ntohs(tcp->window));
	printf("Checkum : %x\n",ntohs(tcp->check));
	printf("Urgent pointer : %u\n",tcp->urg_ptr>>8);
}


void print_udp_header(const struct udphdr * udp)
{
	printf("**UDP HEADER**\n");
	printf("Port Source : %u\n",ntohs(udp->source>>8));
	printf("Port Destination : %u\n",ntohs(udp->dest>>8));
	printf("Taille : %u\n",ntohs(udp->len));
	printf("Checksum : %u\n",ntohs(udp->check));
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
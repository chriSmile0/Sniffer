#include "fct.h"
#define SIZE_ETHERNET 14

void analyse_offline(char *file)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *open_file = pcap_open_offline(file,errbuf);

	if(open_file == NULL) {
		fprintf(stderr,"Erreur dev non accessible : %s\n",errbuf);
		exit(1);
		//erreur 
	}
	pcap_loop(open_file,-1,got_packet,NULL);//search n packet on handle
	pcap_close(open_file);
}

void analyse_online(pcap_t *handle, char *filtre, bpf_u_int32 net)
{
	// int n = 20; // -1 pour l'infini 
	if(filtre != NULL) {
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		(void) errbuf;
		struct bpf_program fp;		/* The compiled filter expression */ 
		char filter_exp[30];/* The filter expression */;
		snprintf(filter_exp,strlen(filtre)+1,"%s",filtre);
		filter_exp[strlen(filtre)] = '\0';
		printf("filtre : |%s|\n",filter_exp);
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filtre, 
				pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filtre, 
				pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}
	pcap_loop(handle,400,got_packet,NULL); //search n packet on handle
	pcap_close(handle);
	return;
}

void print_addr(struct in_addr ip_addr, int src_or_dst) //0 for src , 1 for dst
{
	char buffer[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &ip_addr, buffer, sizeof( buffer ));
	char *message = (!src_or_dst) ? "source": "destination";
	printf( "adresse %s :%s\n", message,buffer );  
}

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

void print_udp_header(const struct udphdr * udp)
{
	printf("**UDP HEADER**\n");
	printf("Port Source : %u\n",ntohs(udp->source));
	printf("Port Destination : %u\n",ntohs(udp->dest));
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

struct in_addr* cast_uint32_in_in_addr(u_int32_t value) 
{
	struct in_addr *s_a;
	s_a = malloc(sizeof(struct in_addr));
	s_a->s_addr = value;
	(void) s_a;
	return s_a;
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

void print_mac_adr(unsigned long long mac_adr, int src_or_dst)
{
	(void) src_or_dst;
	(void) mac_adr;

}

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



void got_packet(u_char *args, const struct pcap_pkthdr *header,
	const u_char *paquet)
{
	//(void) paquet;
	(void) args;
	(void) header;
	const struct ether_header *ethernet;
	ethernet = (struct ether_header *)(paquet);
	if((ethernet->ether_type<<8) == EDT_IP)
	{
		const struct ip *ip;
		ip = (struct ip*)(paquet + SIZE_ETHERNET);
		unsigned int size_ip;
		size_ip = (ip->ip_hl)*4; // après des recherches j'ai vu que l'on doit faire HEad length*4
		if (size_ip < 20) 
		{
			fprintf(stderr,"Valeur header length incorrect : %u\n", size_ip);
			exit(1);
		}
		print_ip_header(ip);
		
		if((ip->ip_p == 17)) 
		{
			const struct udphdr *udp; /* The UDP header */
			udp = (struct udphdr*)(paquet+SIZE_ETHERNET+size_ip);
			print_udp_header(udp);
			if((udp->source>>8 == 67) || (udp->dest>>8 == 67)) {
				print_udp_header(udp);
				struct bootp *b_p;
				b_p = (struct bootp*)(paquet+SIZE_ETHERNET+size_ip+(sizeof(udp)));
				print_bootp_header(b_p);					
			}
			else if((udp->source>>8 == 53) || (udp->dest>>8 == 53))
			{
				//DNS
				HEADER *dns;
				dns = (HEADER*)(paquet+SIZE_ETHERNET+size_ip+(sizeof(udp)));
				print_dns_header(dns);
				int number_answers_RRs = ntohs(dns->ancount);
				int number_queries = ntohs(dns->qdcount);
				int number_auth_rrs = ntohs(dns->nscount);
				int number_add_rrs = ntohs(dns->arcount);
				if(number_queries != 0) 
				{
					
					/*qur = (struct querry*)(paquet+SIZE_ETHERNET+size_ip+sizeof(udp)+sizeof(dns));
					printf("sizeof(dns) : %ld\n",sizeof(dns));
					//printf("%u\n",qur->type);*/
					char buf[1000];
					char *qname;
					//struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
	

					//struct QUESTION *qinfo = NULL;
					qname = (char*)(paquet+SIZE_ETHERNET+size_ip+sizeof(udp)+sizeof(HEADER)+1);
					snprintf(buf,strlen(qname)+1,"%s",qname);
					buf[strlen(qname)+1] = '\0';
					printf("qname : %s\n",buf);
					//free(qname);
					struct QUESTION *qinfo;
					qinfo = (struct QUESTION*)(paquet+SIZE_ETHERNET+size_ip+sizeof(udp)+sizeof(HEADER)+strlen(buf)+2);
					(void) qinfo;
					printf("type : %d\n",ntohs(qinfo->qtype));
					printf("class : %d\n",ntohs(qinfo->qclass));

					//printf("quinfo -> type : %x\n",qinfo->qclass);
					//printf("%d\n",qur->f_c2);

					if(number_answers_RRs!= 0) 
					{
						//struct RES_RECORD answers[20];
					}

					if(number_auth_rrs != 0) 
					{
						//struct RES_RECORD auth[20]; //the replies from the DNS server
					}

					if(number_add_rrs != 0)
					{
					
						//struct RES_RECORD add[20]; //the replies from the DNS server
						struct RES_RECORD *rr;
						char *lecture;
						lecture = (char*)(paquet+SIZE_ETHERNET+size_ip+sizeof(udp)+sizeof(HEADER)+strlen(buf)+2+sizeof(struct QUESTION));
						printf("sizeof question : %ld\n",sizeof(struct QUESTION));
						printf("name : %s\n",(lecture));
						printf("len lecture : %ld\n",strlen(lecture));
						rr = (struct RES_RECORD*)(paquet+SIZE_ETHERNET+size_ip+sizeof(udp)+sizeof(HEADER)+strlen(buf)+2+sizeof(struct QUESTION)+strlen(lecture)+1);
						(void) rr;
						if(rr != NULL) {
							printf("type %d\n",ntohs(rr->type));
							printf("taille : %d\n",ntohs(rr->data_len));
							
							//printf("%s\n",rr->rdata);
						}
						//printf("%d\n",ntohs(rr->resource->type));

					}
					
					
				}


			}
		}
		else 
		{
			
			const struct tcphdr *tcp;
			tcp = (struct tcphdr*)(paquet+SIZE_ETHERNET+size_ip);
			print_tcp_header(tcp);
			//int off_smtp = (tcp->doff*4);
			int nb_options = (tcp->doff*4)-20;
			const struct tcp_options *tcp_o;
			tcp_o = (struct tcp_options*)(paquet+SIZE_ETHERNET+size_ip+nb_options);
			(void) tcp_o;
			int i = 0;
			printf("<");
			// //***a refaire en switch case et dans une fonction *********************************/
			while(i < nb_options) {
				u_int8_t *taille_paquet;
				taille_paquet = (u_int8_t*)(paquet+SIZE_ETHERNET+size_ip+sizeof(tcp)+nb_options+i);
				taille_paquet += 1;
				if((int)*taille_paquet == 4) 
				{
					printf("sackOk,");
				}
				else if((int)*taille_paquet == 8) 
				{
					struct timestamps *tms;
					tms = (struct timestamps*)(paquet+SIZE_ETHERNET+size_ip+nb_options+i+((int)*taille_paquet));
					printf("timestamp ");
					printf("%d ",ntohl(tms->t1));
					printf("%d ,",ntohl(tms->t2));
				}
				else if((int)*taille_paquet == 3) 
				{
					u_int8_t *wscale;
					wscale = (u_int8_t*)(paquet+SIZE_ETHERNET+size_ip+nb_options+i+((int)*taille_paquet));
					printf("wscale ");
					printf("%d ,",*wscale);
				}
				else if((int)*taille_paquet == 2) 
				{
					u_int16_t *mss;
					mss = (u_int16_t*)(paquet+SIZE_ETHERNET+size_ip+nb_options+i+((int)*taille_paquet));
					printf("mss %d,",ntohl(*mss));
				}
				else {
					printf("nop,");
				}
				i+= ((int)*taille_paquet); //soucis ici avec le http simple (get)

			}
			printf(">\n");
			//check des ports pour savoir si on fait du SMTP ou pas derrière 
			if(((ntohs(tcp->dest) == 25) || (ntohs(tcp->source) == 25)) || 
				((ntohs(tcp->dest) == 587) || ntohs(tcp->source) == 587)){
				const struct smtp *smtp_s;
				smtp_s = (struct smtp*)(paquet+SIZE_ETHERNET+size_ip+(tcp->doff*4));
				int i = 0;
				char cur_char;
				while((cur_char = (char)smtp_s->vend[i])) 
				{
					printf("%c",cur_char);
					i++;
				}
				//FIN !!
					
			}
			else if((ntohs(tcp->dest) == 80) || (ntohs(tcp->source) == 80)) {
				//HTTP
				const struct smtp *smtp_s;
				smtp_s = (struct smtp*)(paquet+SIZE_ETHERNET+size_ip+(tcp->doff*4));
				int i = 0;
				char cur_char;
				while((cur_char = (char)smtp_s->vend[i])) 
				{
					printf("%c",cur_char);
					i++;
				}
			}
			else if(((ntohs(tcp->dest) == 21) || (ntohs(tcp->source) == 21))) {
				//FTP
				const struct smtp *smtp_s;
				smtp_s = (struct smtp*)(paquet+SIZE_ETHERNET+size_ip+(tcp->doff*4));
				int i = 0;
				char cur_char;
				while((cur_char = (char)smtp_s->vend[i])) 
				{
					printf("%c",cur_char);
					i++;
				}
			}
			else if(((ntohs(tcp->dest) == 23) || (ntohs(tcp->source) == 23))) {
				//Telnet 
			}
			
		}
	}
	else if(ethernet->ether_type == EDT_ARP)
	{
		const struct ether_arp *arp;
		arp = (struct ether_arp*)(paquet + SIZE_ETHERNET);
		print_arp_header(arp);
	}
	else {
		printf("print RARP \n");
	}
	return;
}
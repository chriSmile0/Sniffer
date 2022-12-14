#include "../inc/fct.h"
#include "../inc/ip_inc.h"
#include "../inc/ether_inc.h"
#include "../inc/arp_rarp.h"

#define SIZE_ETHERNET 14

void analyse_offline(char *file, int verbose)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *open_file = pcap_open_offline(file,errbuf);

	if(open_file == NULL) {
		fprintf(stderr,"Erreur dev non accessible : %s\n",errbuf);
		exit(1);
		//erreur 
	}
	arguments arg[1] = {{verbose}};
	pcap_loop(open_file,-1,(pcap_handler)got_packet,(u_char*)arg);//search n packet on handle
	pcap_close(open_file);
}

void analyse_online(pcap_t *handle, char *filtre, bpf_u_int32 net, int verbose)
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
	arguments arg[1] = {{verbose}};
	pcap_loop(handle,400,(pcap_handler)got_packet,(u_char*)arg); //search n packet on handle
	pcap_close(handle);
	return;
}





void got_packet(arguments args[], const struct pcap_pkthdr *header, const u_char *paquet)
{
	(void) header;
	int verbose = args[0].verbose;
	const struct ether_header *ethernet;
	ethernet = (struct ether_header *)(paquet);
	print_ethernet_header(ethernet);
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
			const struct udphdr *udp; // The UDP header 
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
			//int i = 0;
			printf("<");
			// //***a refaire en switch case et dans une fonction *********************************/
			/*while(i < nb_options) {
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

			}*/
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
				printf("http \n");
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
	else if(ntohs(ethernet->ether_type) == EDT_ARP)
	{
		const struct ether_arp *arp;
		arp = (struct ether_arp*)(paquet + SIZE_ETHERNET);
		print_arp_header(arp,verbose);
	}
	else {
		printf("print RARP \n");
	}
	return;
}
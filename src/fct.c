#include "../inc/fct.h"
#include "../inc/ip_inc.h"
#include "../inc/tcp_inc.h"
#include "../inc/ether_inc.h"
#include "../inc/arp_rarp.h"

#define SIZE_ETHERNET 14

void analyse_offline(char *file, int verbose)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *open_file = pcap_open_offline(file,errbuf);

	if(open_file == NULL) 
	{
		fprintf(stderr,"Erreur dev non accessible : %s\n",errbuf);
		exit(1);
	}
	arguments arg[1] = {{verbose}};
	pcap_loop(open_file,-1,(pcap_handler)got_packet,(u_char*)arg);//search n packet on handle
	pcap_close(open_file);
}

void analyse_online(pcap_t *handle, char *filtre, bpf_u_int32 net, int verbose)
{
	if(filtre != NULL) 
	{
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		(void) errbuf;
		struct bpf_program fp;		/* The compiled filter expression */ 
		char filter_exp[30];/* The filter expression */;
		snprintf(filter_exp,strlen(filtre)+1,"%s",filtre);
		filter_exp[strlen(filtre)] = '\0';
		printf("filtre : |%s|\n",filter_exp);
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
		{
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filtre, 
				pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
		if (pcap_setfilter(handle, &fp) == -1) 
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", filtre, 
				pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}
	arguments arg[1] = {{verbose}};
	pcap_loop(handle,-1,(pcap_handler)got_packet,(u_char*)arg); //search n packet on handle
	pcap_close(handle);
	return;
}





void got_packet(arguments args[], const struct pcap_pkthdr *header, const u_char *paquet)
{
	(void) header;
	int verbose = args[0].verbose;
	const struct ether_header *ethernet;
	ethernet = (struct ether_header *)(paquet);
	print_ethernet_header(ethernet,verbose);
	if(ntohs(ethernet->ether_type)  == EDT_IP)
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
		print_ip_header(ip,verbose);
		
		if((ip->ip_p == 17)) 
		{
			const struct udphdr *udp; // The UDP header 
			udp = (struct udphdr*)(paquet+SIZE_ETHERNET+size_ip);
			print_udp_header(udp,verbose);
			if((udp->source>>8 == 67) || (udp->dest>>8 == 67)) 
			{
				struct bootp *b_p;
				b_p = (struct bootp*)(paquet+SIZE_ETHERNET+size_ip+(sizeof(udp)));
				print_bootp_header(b_p,verbose);					
			}
			else if((udp->source>>8 == 53) || (udp->dest>>8 == 53))
			{
				//DNS
				HEADER *dns;
				dns = (HEADER*)(paquet+SIZE_ETHERNET+size_ip+(sizeof(udp)));
				print_dns_header(dns);
			}
		}
		else 
		{
			const struct tcphdr *tcp;
			tcp = (struct tcphdr*)(paquet+SIZE_ETHERNET+size_ip);
			print_tcp_header(tcp,verbose);
			int nb_options = (tcp->doff*4)-20;
			int len_tcp = 20;
			int index_trame = SIZE_ETHERNET+size_ip+len_tcp;
			print_tcp_options(nb_options,index_trame,verbose,paquet);
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
			else if((ntohs(tcp->dest) == 80) || (ntohs(tcp->source) == 80)) 
			{
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
			else if(((ntohs(tcp->dest) == 21) || (ntohs(tcp->source) == 21))) 
			{
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
			else if(((ntohs(tcp->dest) == 23) || (ntohs(tcp->source) == 23))) 
			{
				//Telnet 
				printf("Telnet\n");
			}
			
		}
	}
	else if(ntohs(ethernet->ether_type) == EDT_ARP)
	{
		const struct ether_arp *arp;
		arp = (struct ether_arp*)(paquet + SIZE_ETHERNET);
		print_arp_header(arp,verbose);
	}
	else if(ntohs(ethernet->ether_type) == EDT_RARP) 
	{
		printf("RARP \n");
	}
	else if(ntohs(ethernet->ether_type) == EDT_IP6) 
	{
		printf("IPV6\n");
	}
	return;
}
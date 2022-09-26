#include "fct.h"
#define SIZE_ETHERNET 14



struct cmd_options parse_cmd(int argc, char **argv)
{
    printf("argc: %d , argv[0] : %s\n",argc,argv[0]);
    struct cmd_options c_o;
    int i = 0;
    int value_letter = 0;
    char *return_interface = NULL;
    while(argv[1][i] != '\0')
        i++;
    i--;
    c_o.cmd = argv[1][i];
    snprintf(c_o.options,SIZE_OPTION,"%s",argv[2]);
    printf("where \n");
    c_o.options[strnlen(argv[1],SIZE_OPTION)] = '\0';//possiblement inutile
    //c_o.options[strnlen("FILE",SIZE_OPTION)] = '\0';

    switch (c_o.cmd)
    {
    case 'i': //interface online
        //check de l'interface 
        return_interface = pcap_lookupdev(c_o.options);
        printf("where 2 \n");
        if(return_interface == NULL) 
        {
            fprintf(stderr,"Erreur sur le nom de l'interface \n");
            exit(1);
        }
        else 
        {
            // traitement interface 
            analyse_online(return_interface);
        }
        printf("break \n");
        break;
    case 'o': //interface offline
        //check du fichier + lancement de l'analyse 
        analyse_offline(c_o.options);
        break;
    case 'f': //filtre BPF (optionnel)
        //check du filtre 
        break;
    case 'v': 
        value_letter = (int) c_o.options[0];
        if((value_letter < 49) || (value_letter > 51))
        {
            fprintf(stderr,"Verbose -> [1|2|3] \n");
            exit(1);
        }
        break;
    
    default:
        //error 
        fprintf(stderr,"Commande possible : -[f|i|o|v]");
        exit(1);
        break;
    }

    return c_o; //options et commandes valides 
}


void analyse_offline(char *file)
{
    /*char buf[SIZE_OPTION];
    int fd = open(file,O_RDONLY);
    if(fd == -1) 
    {
        fprintf(stderr,"Erreur ouverture du fichier \n");
        exit(1);
    }
    int read_ = 0;
    int total_size = 0;
    while(read_ = read(fd,buf,SIZE_OPTION) > 0)
    {
        total_size += read;
        //on lit le fichier , //il faut placer le tout dans un plus grand buffer 
    }
    char *full_trame;
    full_trame  = malloc(sizeof(char)*(total_size+1));*/

    /* Decryptage trame */

    //free(full_trame);
    pcap_t *open_file = pcap_open_offline(file,NULL);
    pcap_close(open_file);
}

void analyse_online(char *inter)
{
    (void) inter;

    pcap_t *handle;
    char *interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;//optionnel 
    char filtre_exp[] = "";//23 pour password, 21,  ou "" pour pas de filtre	
    bpf_u_int32 masque; // masque
    bpf_u_int32 rs; //reseau 
    struct pcap_pkthdr en_tete; //en-tête général de la trame
    const unsigned char *paquet;

	// recherche automatique de l'interface si mess->"|" en entrée//
	interface = pcap_lookupdev(errbuf);
	if(interface == NULL) 
    {
        //erreur
    }
    // recherche automatique de l'interface si mess->"|" en entrée//
	if(pcap_lookupnet(interface, &rs, &masque, errbuf) == -1) 
    {
        //erreur
    }
	// Activation du mode promisq //
    // Avec dev precement init //
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf); 
    // 1 pour activer promisq et 1000 de timeout (a changer car 
    // on est en boucle jusqu'à ^C)
	if(handle == NULL) 
    {
        //erreur 
    }
	// si filtre activer 
	if(pcap_compile(handle, &fp, filtre_exp, 0, rs) == -1)
    {
        //erreur
    }
    // si filtre activer 
	if(pcap_setfilter(handle, &fp) == -1)
    {
        //erreur 
    }
	
	paquet = pcap_next(handle, &en_tete);
    printf("find paquet \n");
    (void) paquet;

    /*Print packet */
    
    const struct ethernet_hdr *ethernet;
    const struct ip_hdr *ip;
    const struct udp_hdr *udp; /* The UDP header */
    const struct arp_hdr *arp;
    

    unsigned int size_ip;
    ethernet = (struct ethernet_hdr *)(paquet);
    (void) ethernet;
    ip = (struct ip_hdr*)(paquet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4; // après des recherches j'ai vu que l'on doit faire HEad length*4
    if (size_ip < 20) {
        fprintf(stderr,"Valeur header length incorrect : %u\n", size_ip);
        exit(1);
    }
    print_ip_header(ip);

    udp = (struct udp_hdr*)(paquet+SIZE_ETHERNET+size_ip);

    print_udp_header(udp);

    arp = (struct arp_hdr*)(paquet + SIZE_ETHERNET);
    print_arp_header(arp);

	pcap_close(handle);
    printf("close \n");
	return;
}

void print_addr(struct in_addr ip_addr, int src_or_dst) //0 for src , 1 for dst
{
    char buffer[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &ip_addr, buffer, sizeof( buffer ));
    char *message = (!src_or_dst) ? "source": "destination";
    printf( "adresse %s :%s\n", message,buffer );  
}

void print_ip_header(const struct ip_hdr * ip)
{
    printf("**IP HEADER**\n");
    printf("Version : %u\n",IP_V(ip));
    printf("IHL : %u\n",IP_HL(ip));

    printf("ip tos : %u\n",IP_TS(ip));
    printf("ip taille : %u\n",IP_LEN(ip));

    printf("time to live : %u\n",(ip)->time_tl);

    printf("prot : %u\n",((ip)->prot));//good 
    print_addr(ip->src_adr,0);
    print_addr(ip->dst_adr,1); 
}

void print_udp_header(const struct udp_hdr * udp)
{
    printf("**UDP HEADER**\n");
    printf("Port Source : %u\n",udp->udp_sp);
    printf("Port Destination : %u\n",udp->udp_dp);
    printf("Taille : %u\n",udp->udp_len);
    printf("Checksum : %u\n",udp->udp_sum);
}

void print_tcp_header(const struct tcp_hdr *tcp)
{
    printf("**TCP HEADER**\n");
    printf("Port Source : %u\n",tcp->tcp_sp);
    printf("Port Destination : %u\n",tcp->tcp_dp);
    printf("Sequence number : %lu\n",tcp->tcp_seq_num);
    printf("Acknowledgment number : %lu\n",tcp->tcp_ack_num);
    printf("offset : %u\n",TCP_OFF(tcp));
    printf("Reserved : %u\n",TCP_RSRV(tcp));
    printf("Checkum : %u\n",tcp->tcp_checksum);
}

void print_mac_adr(unsigned long long mac_adr, int src_or_dst)
{
    (void) src_or_dst;
    (void) mac_adr;

}

void print_arp_header(const struct arp_hdr *arp)
{
    printf("**ARP HEADER**\n");
    printf("Hardware type : \n");
    printf("Protocole : \n");
    printf("Type d'adresse physique \n");
    printf("Taille du type de protocole : \n");
    printf("Operation : \n");
    printf("%d\n",ETH_ALEN);
    (void) arp;
}
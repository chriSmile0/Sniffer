#include <arpa/inet.h>
/* Ethernet header */
/*struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; //Destination host address /
	u_char ether_shost[ETHER_ADDR_LEN]; // Source host address///
	u_short ether_type; // IP? ARP? RARP? etc 
};*/

/* IP header */
/*struct sniff_ip {
	u_char ip_vhl;		// version << 4 | header length >> 2 //
	u_char ip_tos;		// type of service //
	u_short ip_len;		// total length //
	u_short ip_id;		// identification //
	u_short ip_off;		// fragment offset field //
	u_char ip_ttl;		// time to live //
	u_char ip_p;		// protocol //
	u_short ip_sum;		// checksum //
	struct in_addr ip_src,ip_dst; // source and dest address //
};*/


/* Ethernet Header */

struct ethernet_hdr {
	unsigned char dst_ethernet[ETHER_ADDR_LEN];
	unsigned char src_ethernet[ETHER_ADDR_LEN];
	unsigned char data_type;
};


/* Ip Header */ 

struct ip_hdr {
	unsigned char vhl;
	unsigned char type_s;
	unsigned short len;
	unsigned short id;
	unsigned short frag_offs;
	unsigned char time_tl;
	unsigned char prot;
	unsigned short checksum;
	struct in_addr src_adr,dst_adr;
};




// Code récup //Attention bien expliqué //
#define IP_HL(ip)		(((ip)->vhl) & 0x0f) /* = ip & 00001111 */ // code sur 4 bit aussi 
#define IP_V(ip)		(((ip)->vhl) >> 4) /* = ip_vhl décallé de 4 bit */ // code sur 4

// Home made 
// Good
#define IP_TS(ip)		(((ip)->type_s))
#define IP_LEN(ip)		(((ip)->len) >> 8) // code sur 8 
#define IP_ID(ip)		(((ip)->id))
#define IP_OFF(ip)		(((ip)->frag_offs))
#define IP_TL(ip)		(((ip->time_tl)))
#define IP_CHKS(ip)		(((ip)->checksum))
#define IP_P(ip)		(((ip)->p)) // Good 17 pour UDP , 6 pour tcp 


/* UDP header */
struct udp_hdr {
	unsigned char udp_sp;
	unsigned char udp_dp;
	unsigned char udp_len;
	unsigned char udp_sum;
};


/* TCP HEADER */
struct tcp_hdr {
	unsigned short tcp_sp;
	unsigned short tcp_dp;
	unsigned long  tcp_seq_num;
	unsigned long  tcp_ack_num;
	unsigned short offset_flags_win; // >> 4 pour dataoffset
	unsigned short tcp_checksum;
					
};
/** Explications pour le champ offset_flags_win
 * pour reservé on peut utiliser offset... & 0x01ff pour voir sa valeur 
 * pour reserver on décal à droite de 3 donc >> 3 sur offset_flags_win
 * pour le champ de 1 bit après reservé on décalle de 4 donc >> 4
*/

#define TCP_OFF(tcp)	(((tcp)->offset_flags_win >> 12)) // donne bien l'offset car on est sur 16 bits sur un short 
#define TCP_RSRV(tcp)	(((tcp)->offset_flags_win >> 9)&1)// & 0x) // normalement les 3 sont a 0 
#define TCP_ECNS(tcp)	(((tcp)->offset_flags_win >> 8)&1)
#define TCP_CWR(tcp)	(((tcp)->offset_flags_win >> 7)&1)
#define TCP_ECE(tcp)	(((tcp)->offset_flags_win >> 6)&1)
#define TCP_URG(tcp)	(((tcp)->offset_flags_win >> 5)&1)
#define TCP_ACK(tcp)	(((tcp)->offset_flags_win >> 4)&1)
#define TCP_PSH(tcp)	(((tcp)->offset_flags_win >> 3)&1)
#define TCP_RST(tcp)	(((tcp)->offset_flags_win >> 2)&1)
#define TCP_SYN(tcp)	(((tcp)->offset_flags_win >> 1)&1)
#define TCP_FIN(tcp)	(((tcp)->offset_flags_win >> 0)&1)


/* ARP HEADER */

struct arp_hdr {
	unsigned short arp_hard_t;
	unsigned short arp_prot;
	unsigned char arp_hard_adr_len;
	unsigned char arp_prot_adr_len;
	unsigned short arp_ope;
	unsigned long arp_send_hard_adr;//mac a mettre sur 48 bit
	unsigned long arp_send_prot_adr;//ip 
	unsigned long arp_dest_hard_adr;//mac a mettre sur 48 bit
	unsigned long arp_dest_prot_adr;//ip
};
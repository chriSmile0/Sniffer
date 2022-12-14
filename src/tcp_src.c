#include "../inc/tcp_inc.h"

void print_tcp_header(const struct tcphdr *tcp, int verbose)
{

    u_int8_t s = ntohs(tcp->source);
	u_int8_t d = ntohs(tcp->dest);
	u_int8_t se = ntohs(tcp->seq);
	u_int8_t a = ntohs(tcp->ack_seq);
    u_int8_t tab[8] = {tcp->res1,tcp->res2,tcp->urg,tcp->ack,tcp->psh,
                    tcp->rst,tcp->syn,tcp->fin};
    char tab_str[6][3] = {"Urg","Ack","Psh","Rst","Syn","Fin"};
    char flags[19];
    int index_concat = 0;
    for(int i = 0 ; i < 6 ; i++) {
        if(tab[i+2] == 1) {
            snprintf(flags+index_concat,30,"%s",tab_str[i]);
            index_concat += 3;
        }
    }
    flags[index_concat] = '\0';

    if(verbose == 1) {
        printf(" *TCP:* s-d:%u-%u seq-ackseq: %u-%u flgs %s",s,d,se,a,flags);
    }
    else if(verbose == 2) {
        printf("\n\t\t**TCP HEADER** : Psrc: %u Pdst: %u seq: %x ack-seq: %x",
            s,d,se,a);
        printf(" offset: %u flags : %s",tcp->doff,flags);
    }
    else {
        printf("**TCP HEADER**\n");
        printf("Port Source : %u\n",ntohs(tcp->source));
        printf("Port Destination : %u\n",ntohs(tcp->dest));
        printf("Sequence number : %x\n",ntohs(tcp->seq));
        printf("Acknowledgment number : %x\n",ntohs(tcp->ack_seq));
        printf("Off : %u\n",tcp->doff);
        printf("Res1 : %u\n",tcp->res1);
        printf("Res2 : %u\n",tcp->res2);
        printf("Urg : %u\n",tcp->urg);
        printf("Ack : %u\n",tcp->ack);
        printf("Psh :%u\n",tcp->psh);
        printf("Rst :%u\n",tcp->rst);
        printf("Syn :%u\n",tcp->syn);
        printf("Fin :%u\n",tcp->fin);
        printf("Window : %u\n",ntohs(tcp->window));
        printf("Checkum : %x\n",ntohs(tcp->check));
        printf("Urgent pointer : %u\n",tcp->urg_ptr>>8);
    }
}

void print_tcp_options(int len_tcp, int index_trame, int verbose,  
    const u_char *paquet)
{
    // que pour verbose 3 
    int options = 0;
    int taille_options = 0;
    u_int8_t *t_op;
    int cpt_options = 0;
    
    printf("len_tcp : %d\n",len_tcp);
    if(verbose == 3) {
        int i = 0;
        printf("<");
        while(i < len_tcp) {
            u_int8_t *b;
			b = (u_int8_t *)(paquet+index_trame+i);
            if((options != 0) && (cpt_options == taille_options)) {
                options = 0;
                cpt_options = 0;
            }
            if(options != 0) {
                printf("%x ",*b);
                cpt_options++;
            }

            if((int)*b == 1) {
                printf(",nop ");
            }
            else if((int)*b == 8) {
                printf(",timestamp ");
                i++;
                options = 8;
                t_op = (u_int8_t *)(paquet+index_trame+i);
                taille_options = (int)*t_op - 2;
            }
            else if((int)*b == 3) {
                printf(",scale ");
                i++;
                options = 3;
                t_op = (u_int8_t *)(paquet+index_trame+i);
                taille_options = (int)*t_op;

            }
            else if((int)*b == 4) {
                printf(",Sackok ");
                i++;
            }
            else if((int)*b == 2) {
                printf(",Mss ");
                i++;
                options = 2;
                taille_options = options;
            }
            i++;
        }
        printf(">\n");
    }
}


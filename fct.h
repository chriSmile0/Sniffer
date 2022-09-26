#ifndef FCT_H
#define FCT_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "lib_net.h"
#include "lib_netinet.h"
#include "headers.h"
#include "bootp.h"

#define SIZE_OPTION 1024



struct cmd_options {
    char cmd;
    char options[SIZE_OPTION];
};

struct list_cmd_options {
    struct cmd_options *tab_options;
};


/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

struct cmd_options parse_cmd(int argc, char **argv);



/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

void analyse_offline(char *file);

/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/


void analyse_online(char *interface);


/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

void decryptage_trame(char *trame);


void print_addr(struct in_addr ip_addr, int src_or_dst); // print addr to format #.#.#.#. or 1:1:1:1:1:1:

void print_ip_header(const struct ip_hdr * ip);

void print_udp_header(const struct udp_hdr * udp);

void print_tcp_header(const struct tcp_hdr *tcp);


#endif /* FCT_H */
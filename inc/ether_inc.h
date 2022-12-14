#ifndef ETHER_INC_H
#define ETHER_INC_H
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>



/**
 * @version 1.0
 * 
 * @brief
 * 
 * @param[:]
 * 
 * @return 
*/

void print_ethernet_header(const struct ether_header *ether, int verbose);

#endif // ETHER_INC_H
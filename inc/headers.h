#include <arpa/inet.h>
#include <arpa/ftp.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <arpa/telnet.h>
#include "lib_net.h"
#include "lib_netinet.h"
//lib
#include <stdio.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>


struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

struct RES_RECORD
{
    unsigned short type;
    unsigned short data_len;
    /*unsigned short _class;
    unsigned int ttl;
    unsigned char *rdata;*/
};

//tcp options 

// creer une struct smtp 

struct smtp {
    u_int8_t vend[128];
};

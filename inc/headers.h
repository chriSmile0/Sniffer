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
    unsigned short type;
    unsigned short class;
};

struct RES_RECORD
{
    unsigned short type;
    unsigned short class;
    unsigned short ttl;
    unsigned short data_len;
};

struct ANS_RECORD
{
    unsigned short type;
    unsigned short class;
};

struct smtp {
    u_int8_t vend[128];
};
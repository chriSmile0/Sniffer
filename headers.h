#include <arpa/inet.h>
#include <arpa/ftp.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <arpa/telnet.h>
#include "lib_net.h"
#include "lib_netinet.h"


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
struct tcp_options {
    u_int8_t t_opt1; //minimum
    u_int8_t t_opt2; //minimum
    u_int8_t t_opt3; //minimum
    u_int32_t t1;
    u_int32_t t2;
};

struct timestamps {
    u_int32_t t1;
    u_int32_t t2;
};

// creer une struct smtp 

struct smtp {
    u_int8_t vend[128];
};

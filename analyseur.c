#include "fct.h"




int main(int argc, char **argv)
{
    if(argc < 2) {
        fprintf(stderr,"Format : %s -[options] \n",argv[0]);
		return 1;
	}
	struct cmd_options c_o_return = parse_cmd(argc,argv);
	printf("cmd : %c, options : %s\n",c_o_return.cmd,c_o_return.options);
	
    return 0;
}
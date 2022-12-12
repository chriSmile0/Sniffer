#include "fct.h"
#include <getopt.h>

int main(int argc, char *argv[]) {
	extern int optind;
	static struct option options[] = {
		{"-i", required_argument,NULL,'i'}, //verbose + filtre en option
		{"-o", required_argument, NULL, 'o'},// verbose 
		{NULL, 0, NULL, 0}
	};
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp = NULL;
	pcap_if_t *device;
	int opt, index = 0;
	char *filtre = NULL;
	char *file = NULL;
	char *dev = NULL;
	int verbose = 0;
	char mode = 'x';
	while ((opt = getopt_long(argc, argv, "i:o:", options, &index)) != -1) {
		switch (opt) {
			/* Inline */
			case 'i':
				printf("*** Inline ***\n");
				optind = 2;
				if(strcmp("-v",optarg) == 0) {
					optind = 3;
					verbose = atoi(argv[optind]);
					if(verbose < 4 && verbose > 0) {
						mode = 'i';
						if((++optind < argc)&&(strcmp("-f",argv[optind]) == 0)) {
							filtre = malloc(20);//taille max du filtre
							filtre[0] = '\0';
							snprintf(filtre,19,"%s",argv[++optind]);
						}
					}
					else {
						fprintf(stderr,"usage : -v [1|2|3] \n");
						return EXIT_FAILURE;
					}
				}
				else {
					if(argv[optind][0] != '-'){ //ce n'est pas une interface mais l'option suivante
						dev = malloc(strlen(argv[optind])+1);
						snprintf(dev,strlen(argv[optind])+1,"%s",argv[optind]);
						dev[strlen(argv[optind])] = '\0';
						optind = 3;
						if(strcmp("-v",argv[optind]) == 0) {
							optind = 4;
							verbose = atoi(argv[optind]);
							if(verbose < 4 && verbose > 0) {
								mode = 'i';
								if((++optind < argc)&&(strcmp("-f",argv[optind]) == 0)) {
									filtre = malloc(20);//taille max du filtre
									filtre[0] = '\0';
									snprintf(filtre,19,"%s",argv[++optind]);
								}
							}
						}
						else {
							fprintf(stderr,"usage : -v [1|2|3] \n");
							return EXIT_FAILURE;
						}

					}
					else {
						fprintf(stderr,"usage %s -i {options:<interface>} -v [1|2|3]\n",argv[0]);
						return EXIT_FAILURE;
					}
				}
				break;
			/* Offline */
			case 'o':
				printf("*** Offline ***\n");
				if(strlen(optarg)!=0) { //file 
					optind = 2;
					file = malloc(strlen(argv[optind])+1);
					snprintf(file,strlen(argv[optind])+1,"%s",argv[optind]);
					file[strlen(argv[optind])] = '\0';
					if(strcmp("-v",argv[++optind]) != 0) {
						fprintf(stderr,"usage : <file> -v [1|2|3] \n");
						return EXIT_FAILURE;
					}
					verbose = atoi(argv[++optind]);
					if(verbose < 1 || verbose > 3) {
						fprintf(stderr,"usage : %s -o <file> -v [1|2|3]\n",argv[0]);
						return EXIT_FAILURE;
					}
					mode = 'o';
				}
				else {
					fprintf(stderr,"usage %s -o <file> -v [1|2|3]\n",argv[0]);
					return EXIT_FAILURE;
				}
				break;
			default:
				break;
		}
	}

	printf("verbose : %d\n",verbose);
	printf("mode : %c\n",mode);
	
	if(mode == 'o') {
		//Offline : verbose [1|2|3] mode : o , filtre = NULL
		printf("File : %s\n",file);
		analyse_offline(file);
		if(file != NULL)
			free(file);
	}
	else {
		//Inline : verbose [1|2|3] mode : i , filtre = NULL | filtre != NULL
		printf("filtre : %s\n",(filtre != NULL) ? filtre : "NULL");
		printf("device : %s\n",(dev != NULL) ? dev : "NULL");
		pcap_t *handle;
		bpf_u_int32 mask;		/* The netmask of our sniffing device */
		bpf_u_int32 net;		/* The IP of our sniffing device */
		if(dev != NULL) {
			if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
				fprintf(stderr, "Can't get netmask for device %s\n", dev);
				net = 0;
				mask = 0;
			}
			handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf); 
			// 1 pour activer promisq et 1000 de timeout (a changer car 
			// on est en boucle jusqu'à ^C)
			if (handle == NULL)  {
				fprintf(stderr,"Erreur dev %s non accessible : %s\n",dev,errbuf);
				return EXIT_FAILURE;
			}
			else {
				analyse_online(handle,filtre,net);
			}
		}
		else {
			pcap_findalldevs(&alldevsp,errbuf);
			device = alldevsp;
			if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1) {
				fprintf(stderr, "Can't get netmask for device %s\n", device->name);
				net = 0;
				mask = 0;
			}
			handle = pcap_open_live(device->name, BUFSIZ, 1, 10000, errbuf); 
			if (handle == NULL)  {
				fprintf(stderr,"Erreur dev %s non accessible : %s\n",dev,errbuf);
				return EXIT_FAILURE;
			}
			else {
				analyse_online(handle,filtre,net);
			}
		}
		if(dev == NULL)
			free(dev);
		if(filtre != NULL)
			free(filtre);
	}
	return EXIT_SUCCESS;
}
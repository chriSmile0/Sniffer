#include "fct.h"




int main(int argc, char **argv)
{
    if(argc < 2) {
        fprintf(stderr,"Format : %s -[options] \n",argv[0]);
		return 1;
	}
	/*struct cmd_options c_o_return = parse_cmd(argc,argv);
	printf("cmd : %c, options : %s\n",c_o_return.cmd,c_o_return.options);*/
	int c = 61; //00111101 = 61 // >> on part de l'arrière vers l'avant 
	printf("%d\n",(c>>4)); // renvoie la première partie de l'hexa

	printf("%d\n",c & 0x0f); // renvoie la 2ème partit de nombre hexa


	// on va compliquer avec un nombre sur 3 chiffres hexa donc 2^12
	int x = 1950; //0111|1001|1110 = 1950
	printf("%d\n",x>>4); // x>>4 = 0111|1001 , on enlève la fin 
	printf("%d\n",x>>8); // x>>8 = 0111, on enlève les 2 octets de la fin 

	printf("%d\n",x & 0x0f0); // normalement me donne l'hexa du milieu, = 1001|1110 faux donc me donne la fin 
	printf("%d\n",x & 0x00f); // me donne la fin 
	printf("%d\n",x & 0xf00); // me donne le début avec sa vrai valeur et non pas son véritable off set (pour l'obtenir je doit remonter de 8 ->)
	printf("%d\n",(x & 0xf00) >> 8); // j'obtiens bien 7 

	// Maintenant si je veux juste la valeur de l'hexa du milieu je doit procéder ainsi 
	printf("%d\n",(x>>4) & 0x0f); //j'obtiens bien 9 qui est la valeur 1001 qui est l'offset du milieu 
	//attention au variations avec tcp avec des champs de 3 bits et non 4 


	// on passe maintenant sur un nombre sur 4 chiffres hexa donc 2^16
	int z = 15671; //0011|1101|0011|0111 ) 15671 en hexa

	// on cherche a print celui du milieu a gauche 
	printf("%d\n",(z>>8)); // = 61 car il reste 0011|1101
	printf("%d\n",(z>>8)& 0x0f); // j'obtiens bien 13 qui est bien 1101
	printf("%d\n",(z>>8)& 0xf0); // = 48 = 0011|0000 

	// a donc bien 13 on veut maintenant voir si on peut faire le bit a bit et pour cela on doit trouver les bonnes lettres de l'alphabet hexa
	// ***** Les bonnes lettress sont les suivantes : e pour 1110 , c pour 1100 et 8 pour 1000

	//donc si on veut le 11 eme bit sur les 16 on peut faire comme ceci ->
	printf("%d\n",(z>>1&1)); // on obtient bien 1 

	// ou comme ceci : 
	
    return 0;
}
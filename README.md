# Analyseur réseau 
Le mode inline/offline est implémenté est fonctionnel 
    Reconnaissance de l'ipv4: 
        Reconnaissance de l'udp (implémenté) :
            Reconnaissance de bootp/dhcp valide (affichage via verbosité niveau 3) (implementé)
            Reconnaissance du dns (invalide)

        Reconnaissance de tcp (implémenté) :
            Reconnaissance des options TCP (implémenté)
            Reconnaissance de stmp (implémenté)
            Reconnaissance de http (implémenté)
            Reconnaissance de ftp  (implémenté)

    Reconnaissance de l'ipv6:
        -/
    Reconnaissance de l'ARP:
        - Décodage trame ARP (implémenté)
    Reconnaissance du RARP
        -/

Filtrage (implémenté mais pas certain que cela soit fonctionnel)
Verbosité (implémenté)
Makefile (implémenté + bonus d'éxécution)

Le DNS et le Telnet ainsi que POP ne sont pas implémentés 
Il manque aussi l'interruption unique du processus via ^C
    (toujours possible avec ^Z) 
    manquement de la gestion des signaux associés pour cela
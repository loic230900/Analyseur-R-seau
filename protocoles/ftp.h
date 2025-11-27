#ifndef FTP_H
#define FTP_H

#ifndef u_char
typedef unsigned char u_char;
#endif

/**
 * Analyse un paquet FTP et affiche un résumé selon le niveau de verbosité 2 ou 3.
 * @param packet    Pointeur vers le début du payload TCP contenant les données FTP.
 * @param length    Longueur du payload TCP disponible
 * @param verbosity Niveau de verbosité (2 ou 3) 
 * @param indent    Indentation en espaces pour l'affichage
 * @return          Nombre d'octets consommés dans le payload TCP pour le protocole FTP.
 */
int parse_ftp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 pour FTP (commande ou code de réponse).
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_tcp_payload  Offset du début du payload TCP (après TCP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
 */
int ftp_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/* Ports FTP */
#define FTP_PORT_CONTROL    21  
#define FTP_PORT_DATA       20  

/* Commande FTP utilisée pour le masquage du mot de passe */
#define FTP_CMD_PASS    "PASS"  

#endif /* FTP_H*/
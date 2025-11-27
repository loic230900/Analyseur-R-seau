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

* Commandes FTP principales */
#define FTP_CMD_USER    "USER"
#define FTP_CMD_PASS    "PASS"
#define FTP_CMD_CWD     "CWD"
#define FTP_CMD_CDUP    "CDUP"
#define FTP_CMD_PWD     "PWD"
#define FTP_CMD_LIST    "LIST"
#define FTP_CMD_NLST    "NLST"
#define FTP_CMD_RETR    "RETR"
#define FTP_CMD_STOR    "STOR"
#define FTP_CMD_DELE    "DELE"
#define FTP_CMD_RMD     "RMD"
#define FTP_CMD_MKD     "MKD"
#define FTP_CMD_QUIT    "QUIT"
#define FTP_CMD_PASV    "PASV"
#define FTP_CMD_PORT    "PORT"
#define FTP_CMD_TYPE    "TYPE"
#define FTP_CMD_MODE    "MODE"
#define FTP_CMD_STRU    "STRU"
#define FTP_CMD_SYST    "SYST"
#define FTP_CMD_HELP    "HELP"
#define FTP_CMD_NOOP    "NOOP"
#define FTP_CMD_SIZE    "SIZE"
#define FTP_CMD_MDTM    "MDTM"
#define FTP_CMD_FEAT    "FEAT"
#define FTP_CMD_OPTS    "OPTS"

/* Codes de réponse FTP  */
#define FTP_CODE_READY           220 
#define FTP_CODE_CLOSING         221  
#define FTP_CODE_DATA_CONN_OPEN  225  
#define FTP_CODE_DATA_CONN_CLOSE 226  
#define FTP_CODE_PASSIVE         227  
#define FTP_CODE_LOGGED_IN       230  
#define FTP_CODE_NEED_PASS       331  
#define FTP_CODE_NEED_ACCT       332  
#define FTP_CODE_FILE_ACTION_OK  250  
#define FTP_CODE_PATH_CREATED    257  
#define FTP_CODE_NEED_PASSIVE    425  
#define FTP_CODE_FILE_UNAVAIL    550  
#define FTP_CODE_ACTION_FAILED   550  
#define FTP_CODE_UNKNOWN_CMD     500  
#define FTP_CODE_BAD_PARAM       501  
#define FTP_CODE_NOT_IMPL        502  
#define FTP_CODE_BAD_SEQUENCE    503  
#define FTP_CODE_NOT_LOGGED_IN   530  

#endif /* FTP_H*/
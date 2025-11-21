#ifndef SMTP_H
#define SMTP_H


#ifndef u_char
typedef unsigned char u_char;
#endif

/**
 * Analyse un paquet SMTP et affiche un résumé selon le niveau de verbosité 2 ou 3.
 * @param packet    Pointeur vers le début du payload TCP contenant les données SMTP.
 * @param length    Longeur du payload TCP disponible
 * @param verbosity Niveau de verbosité (2 ou 3) 
 * @param indent    Indentation en epsaces pour l'affichage
 * @return          Nombre d'octets consommés dans le payload TCP pour le protocole SMTP.
 */
int parse_smtp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 pour SMTP (commande ou code de réponse).
 * 
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_tcp_payload  Offset du début du payload TCP (après TCP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
 */
int smtp_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/* Commandes smtp*/
#define SMTP_CMD_HELLO      "HELO"
#define SMTP_CMD_EHLO       "EHLO"
#define SMTP_CMD_MAIL_FROM  "MAIL FROM"
#define SMTP_CMD_RCPT_TO    "RCPT TO"
#define SMTP_CMD_DATA       "DATA"
#define SMTP_CMD_QUIT       "QUIT"
#define SMTP_CMD_RSET       "RSET"
#define SMTP_CMD_VRFY       "VRFY"
#define SMTP_CMD_NOOP       "NOOP"
#define SMTP_CMD_AUTH       "AUTH"
#define SMTP_CMD_STARTTLS   "STARTTLS"


/* code reponse smtp*/
#define SMTP_CODE_READY             220
#define SMTP_CODE_CLOSING           221
#define SMTP_CODE_OK                250
#define SMTP_CODE_START_MAIL        354
#define SMTP_CODE_UNAVAILABLE       421
#define SMTP_CODE_TEMP_FAIL         450
#define SMTP_CODE_SYNTAX_ERROR      500
#define SMTP_CODE_NOT_IMPL          502
#define SMTP_CODE_BAD_SEQUENCE      503
#define SMTP_CODE_MAILBOX_UNAVAIL   550


#endif /* SMTP_H */
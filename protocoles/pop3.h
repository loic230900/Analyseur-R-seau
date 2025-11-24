#ifndef POP3_H
#define POP3_H

#ifndef u_char
typedef unsigned char u_char;
#endif

#include <stdint.h>
#include <pcap.h>

/**
 * Analyse un paquet POP3 et affiche un résumé selon le niveau de verbosité 2 ou 3.
 * @param packet    Pointeur vers le début du payload TCP contenant les données POP3.
 * @param length    Longueur du payload TCP disponible
 * @param verbosity Niveau de verbosité (2 ou 3) 
 * @param indent    Indentation en espaces pour l'affichage
 * @return          Nombre d'octets consommés dans le payload TCP pour le protocole POP3.
 */
int parse_pop3(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 pour POP3 (commande ou réponse).
 * 
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_tcp_payload  Offset du début du payload TCP (après TCP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
 */
int pop3_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/* Ports POP3 */
#define POP3_PORT_PLAIN 110  // POP3 non-chiffré
#define POP3_PORT_SSL    995  // POP3S (POP3 over TLS/SSL)

/* Commandes POP3 */
#define POP3_CMD_USER    "USER"
#define POP3_CMD_PASS    "PASS"
#define POP3_CMD_APOP    "APOP"
#define POP3_CMD_STAT    "STAT"
#define POP3_CMD_LIST    "LIST"
#define POP3_CMD_RETR    "RETR"
#define POP3_CMD_DELE    "DELE"
#define POP3_CMD_NOOP    "NOOP"
#define POP3_CMD_RSET    "RSET"
#define POP3_CMD_QUIT    "QUIT"
#define POP3_CMD_TOP     "TOP"
#define POP3_CMD_UIDL    "UIDL"
#define POP3_CMD_CAPA    "CAPA"

/* Codes de réponse POP3 */
#define POP3_RESP_OK     "+OK"
#define POP3_RESP_ERR    "-ERR"

#endif /* POP3_H */
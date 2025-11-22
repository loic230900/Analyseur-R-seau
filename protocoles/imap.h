#ifndef IMAP_H
#define IMAP_H

#ifndef u_char
#define u_char unsigned char
#endif

#include <stdint.h>
#include <pcap.h>

/**
 * Analyse et affiche un message IMAP (commande, réponse untaggée/taggée).
 * @param packet    Début du payload TCP supposé IMAP.
 * @param length    Longueur disponible.
 * @param verbosity 2 ou 3.
 * @param indent    Indentation affichage.
 * @return          Octets consommés ou 0 
 */
int parse_imap(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 IMAP
 * @param packet              Paquet complet.
 * @param caplen              Longueur capturée.
 * @param offset_tcp_payload  Offset début payload TCP.
 * @param resume              Buffer résumé.
 * @return 1 si succès, 0 sinon.
 */
int imap_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/* Ports  IMAP */
#define IMAP_PORT_PLAIN 143
#define IMAP_PORT_SSL   993

/* Commandes IMAP */
#define IMAP_CMD_LOGIN      "LOGIN"
#define IMAP_CMD_CAPABILITY "CAPABILITY"
#define IMAP_CMD_SELECT     "SELECT"
#define IMAP_CMD_EXAMINE    "EXAMINE"
#define IMAP_CMD_FETCH      "FETCH"
#define IMAP_CMD_STORE      "STORE"
#define IMAP_CMD_SEARCH     "SEARCH"
#define IMAP_CMD_LOGOUT     "LOGOUT"
#define IMAP_CMD_NOOP       "NOOP"
#define IMAP_CMD_IDLE       "IDLE"

/* Code Reponse */
#define IMAP_RESP_OK        "OK"
#define IMAP_RESP_NO        "NO"
#define IMAP_RESP_BAD       "BAD"
#define IMAP_RESP_PREAUTH   "PREAUTH"
#define IMAP_RESP_BYE       "BYE"


#endif /*IMAP_H*/
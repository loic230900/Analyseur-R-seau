/**

 * Définitions pour l'analyse HTTP
 * 
 * Définitions et prototypes pour le parsing HTTP/1.x (RFCs 7230-7235).
 * Port TCP : 80 (HTTP), 443 (HTTPS/TLS non analysé).
 * 
 */

#ifndef HTTP_H
#define HTTP_H
#ifndef UCHAR_TYPEDEF_GUARD
#define UCHAR_TYPEDEF_GUARD
typedef unsigned char u_char;
#endif

#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>

/* Ports HTTP */
#define HTTP_PORT 80            /* Port standard pour HTTP */
#define HTTPS_PORT 443          /* Port standard pour HTTPS (HTTP sur TLS) */

/**
 * Analyse et affiche un message HTTP(Request ou Reponse).
 * @param packet    Pointeur vers le début du payload TCP contenant HTTP.
 * @param length    Longeur du payload TCP disponible.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espace pour l'affichage.
 * @return          Nombre d'octets consommés (headers + body si détecté),
 *                  ou 0 si ce n'est pas du HTTP ou erreur.
 */
int parse_http(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 pour HTTP (méthode+URI ou code status).
 * @param packet           Pointeur vers le début du paquet complet.
 * @param caplen           Longueur capturée totale.
 * @param offset_tcp_payload Offset du début du payload TCP (après TCP header).
 * @param resume           Buffer de sortie pour le résumé.
 * @return                 1 en succès, 0 en échec.
 */
int http_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/* Ports HTTP */
#define HTTP_PORT_PLAIN 80   // HTTP non-chiffré
#define HTTP_PORT_SSL   443   // HTTPS (HTTP over TLS/SSL)


#endif /* HTTP_H */
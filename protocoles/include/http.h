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
 * Fonction principale de parsing HTTP.
 * Détecte automatiquement le type (requête/réponse/body fragmenté)
 * et route vers le parser approprié.
 * 
 * @param packet    Pointeur vers le début des données HTTP
 * @param length    Longueur des données HTTP
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Indentation pour l'affichage
 * @return          Nombre d'octets consommés
 */
int parse_http(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 pour HTTP.
 * Génère une ligne compacte avec méthode+URI (requête) ou code+status (réponse).
 * Enrichi avec Host (requête) ou Content-Type (réponse) si disponibles.
 * 
 * @param packet             Pointeur vers le paquet complet
 * @param caplen             Longueur capturée
 * @param offset_tcp_payload Offset du payload TCP (début HTTP)
 * @param resume             Buffer de résumé (sortie)
 * @return                   1 si succès, 0 si échec
 */
int http_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/* Ports HTTP */
#define HTTP_PORT_PLAIN 80   // HTTP non-chiffré
#define HTTP_PORT_SSL   443   // HTTPS (HTTP over TLS/SSL)


#endif /* HTTP_H */
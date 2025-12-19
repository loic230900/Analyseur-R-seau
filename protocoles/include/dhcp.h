/**
 * Définitions pour l'analyse DHCP (couche 7 - Application)
 * 
 * Définitions de constantes et prototypes pour DHCP (RFC 2131).
 * Ports UDP : 67 (serveur), 68 (client). Extension de BOOTP.
 * 
 */

#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>
#include <pcap.h>
#include "bootp.h"

/* Ports DHCP (couche 7 sur UDP) */
#define DHCP_SERVER_PORT 67     /* Port serveur DHCP (destination requête client) */
#define DHCP_CLIENT_PORT 68     /* Port client DHCP (source requête client) */

/**
 *  Convertit un type de message DHCP en chaîne lisible
 * @param msg_type Code numérique du type de message DHCP (1-8)
 * @return Chaîne de caractères représentant le type, ou "Unknown"
 */
const char* dhcp_msg_type_to_str(uint8_t msg_type);

/**
 * Analyse et affiche les champs d'un message DHCP (BOOTP).
 * @param packet    Pointeur vers le début de l'en-tête DHCP (BOOTP).
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 */
int parse_dhcp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Génère un résumé succinct d'un message DHCP/BOOTP pour verbosité 1.
 * @param packet                Pointeur vers le début du paquet.
 * @param caplen                Longueur capturée du paquet.
 * @param offset_udp_payload    Offset vers le début de la charge utile UDP (DHCP).
 * @param resume                Buffer de sortie pour le résumé.
 * @return 1 si succès, 0 si échec.
 */
int dhcp_v1_summary(const u_char *packet, int caplen, int offset_udp_payload, char *resume);

#endif /* DHCP_H */

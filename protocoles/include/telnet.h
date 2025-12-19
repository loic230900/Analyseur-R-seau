/**

 * Définitions pour l'analyse Telnet 
 * 
 * Définitions et prototypes pour le parsing Telnet (RFC 854).
 * Port TCP : 23.
 * 
 */

#ifndef TELNET_H
#define TELNET_H

#include <stdint.h>

#ifndef UCHAR_TYPEDEF_GUARD
#define UCHAR_TYPEDEF_GUARD
typedef unsigned char u_char;
#endif

/**
 * Analyse un paquet Telnet et affiche un résumé selon le niveau de verbosité 2 ou 3.
 * @param packet    Pointeur vers le début du payload TCP contenant les données Telnet.
 * @param length    Longueur du payload TCP disponible
 * @param verbosity Niveau de verbosité (2 ou 3) 
 * @param indent    Indentation en espaces pour l'affichage
 * @param src_port  Port source TCP (pour déterminer la direction)
 * @param dst_port  Port destination TCP (pour déterminer la direction)
 * @return          Nombre d'octets consommés dans le payload TCP pour le protocole Telnet.
 */
int parse_telnet(const u_char *packet, int length, int verbosity, int indent, uint16_t src_port, uint16_t dst_port);

/**
 * Résumé verbosité 1 pour Telnet (commande ou données).
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_tcp_payload  Offset du début du payload TCP (après TCP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @param src_port            Port source TCP (pour différencier client/serveur).
 * @param dst_port            Port destination TCP.
 * @return                    1 en succès, 0 en échec.
 */
int telnet_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume, uint16_t src_port, uint16_t dst_port);

/* Port Telnet standard */
#define TELNET_PORT 23

/* Code IAC (Interpret As Command) */
#define TELNET_IAC  255  /* 0xFF - Interpréter comme commande */

#endif /* TELNET_H */
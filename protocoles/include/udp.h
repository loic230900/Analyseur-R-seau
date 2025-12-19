/**

 * Définitions pour l'analyse UDP 
 * 
 * Définitions de constantes et prototypes pour le parsing UDP (RFC 768).
 * En-tête de 8 octets. Protocole IP : 17
 * 
 */

#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <pcap.h>

// en-tête UDP taille constante
#define UDP_HDR_LEN 8

/**
 * Analyse et affiche les champs de l'en-tête UDP.
 * @param packet    Pointeur vers le début de l'en-tête UDP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @param src_port  (sortie) Port source (host byte order).
 * @param dst_port  (sortie) Port destination (host byte order).
 * @return          Taille de l'en-tête UDP (8 octets) ou 0 en cas d'erreur.
 */
int parse_udp(const u_char *packet, int length, int verbosity, int indent, uint16_t *src_port, uint16_t *dst_port);

/**
 * Verbosité 1: ajoute les ports UDP pour les protocoles non reconnus avec format IP:port
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_transport    Offset du début de l'en-tête UDP (après IP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @param src_ip              Adresse IP source (chaîne de caractères).
 * @param dst_ip              Adresse IP destination (chaîne de caractères).
 * @return                    1 en succès, 0 en échec.
 */
int udp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, 
                         char *resume, const char *src_ip, const char *dst_ip);

#endif /* UDP_H */

#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <pcap.h>

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

/* Verbosité 1: ajoute ports génériques src>dst si pas application reconnue */
int udp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, char *resume);

#endif /* UDP_H */

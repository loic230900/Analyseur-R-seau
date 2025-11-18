#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <pcap.h>

/**
 * Analyse et affiche les champs de l'en-tête TCP.
 * @param packet    Pointeur vers le début de l'en-tête TCP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @param src_port  (sortie) Port source TCP. 
 * @param dst_port  (sortie) Port destination TCP. 
 * @param flags     (sortie) Flags TCP (URG, ACK, PSH, RST, SYN, FIN).
 * @return          Taille de l'en-tête TCP (IHL*4) ou 0 en cas d'erreur.
 */
int parse_tcp(const u_char *packet, int length, int verbosity, int indent, uint16_t *src_port, uint16_t *dst_port, uint8_t *flags);

/* Verbosité 1: ajoute SYN/SYN-ACK/FIN/RST/ACK/PSH-ACK */
int tcp_v1_flags_summary(const u_char *packet, int caplen, int offset_transport, char *resume);

#endif /* TCP_H */
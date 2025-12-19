/**
 * Définitions pour l'analyse TCP (couche 4 - Transport)
 * 
 * Définitions de constantes et prototypes pour le parsing TCP (RFC 793).
 * En-tête de 20-60 octets (data offset * 4). Protocole IP : 6
 * 
 */

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

/**
 * Verbosité 1: ajoute SYN/SYN-ACK/FIN/RST/ACK/PSH-ACK
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_transport    Offset du début de l'en-tête TCP (après IP header).
 * @param payload_len         Longueur du payload TCP (données).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
 *  */
int tcp_v1_flags_summary(const u_char *packet, int caplen, int offset_transport, int payload_len, char *resume);

/**
 * Verbosité 1: ajoute les ports TCP pour les protocoles non reconnus
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_transport    Offset du début de l'en-tête TCP (après IP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
*/
int tcp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, char *resume);

#endif /* TCP_H */
/**

 * Définitions pour l'analyse IPv6
 * 
 * Définitions de constantes et prototypes pour le parsing IPv6 (RFC 8200).
 * En-tête fixe de 40 octets + extension headers. EtherType : 0x86DD
 * 
 */

#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
#include <pcap.h>

/**
 * Analyse et affiche les champs de l'en-tête IPv6.
 * @param packet    Pointeur vers le début de l'en-tête IPv6.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @param next_hdr  (sortie) Champ "Next Header" (type du protocole suivant).
 * @return          Taille de l'en-tête IPv6 (40 octets) ou 0 en cas d'erreur.
 */
int parse_ipv6(const u_char *packet, int length, int verbosity, int indent, uint8_t *next_hdr);

#endif /* IPV6_H */

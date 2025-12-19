/**
 * Définitions pour l'analyse IPv4 (couche 3 - Réseau)
 * 
 * Définitions de constantes et prototypes pour le parsing IPv4 (RFC 791).
 * En-tête de 20-60 octets. EtherType : 0x0800
 * 
 */

#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <sys/types.h>
#include <pcap.h>

/**
 * Analyse et affiche les champs de l'en-tête IPv4.
 * @param packet    Pointeur vers le début de l'en-tête IPv4.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @param protocol  (sortie) Champ "protocol" de l'IP (ex. UDP=17, TCP=6).
 * @return          Taille de l'en-tête IPv4 (IHL*4) ou 0 en cas d'erreur.
 */
int parse_ipv4(const u_char *packet, int length, int verbosity, int indent, uint8_t *protocol);

#endif /* IPV4_H */

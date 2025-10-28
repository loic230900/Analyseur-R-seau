#ifndef ICMPV6_H
#define ICMPV6_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

// Définition du protocole ICMPv6 si non disponible
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/**
 * Analyse et affiche les champs de l'en-tête ICMPv6.
 * Délègue au parser NDP si c'est un message NDP (types 133-137).
 * @param packet    Pointeur vers le début de l'en-tête ICMPv6.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @return          Taille traitée ou 0 en cas d'erreur.
 */
int parse_icmpv6(const u_char *packet, int length, int verbosity, int indent);

/**
 * Retourne le nom du type ICMPv6.
 * @param type      Type ICMPv6.
 * @return          Nom du type en chaîne de caractères.
 */
const char* get_icmpv6_type_name(uint8_t type);

#endif /* ICMPV6_H */
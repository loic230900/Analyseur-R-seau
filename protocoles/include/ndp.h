/**
 * Définitions pour l'analyse NDP (Neighbor Discovery Protocol)
 * 
 * Définitions pour NDP (RFC 4861), sous-ensemble d'ICMPv6 (types 133-137).
 * 
 */

#ifndef NDP_H
#define NDP_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

// Types d'options NDP
#define ND_OPT_SOURCE_LINKADDR      1
#define ND_OPT_TARGET_LINKADDR      2
#define ND_OPT_PREFIX_INFORMATION   3
#define ND_OPT_REDIRECTED_HEADER    4
#define ND_OPT_MTU                  5

/**
 * Analyse et affiche un message NDP complet.
 * @param packet    Pointeur vers le début du message ICMPv6/NDP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @return          Taille traitée ou 0 en cas d'erreur.
 */
int parse_ndp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Analyse les options TLV d'un message NDP.
 * @param options   Pointeur vers le début des options.
 * @param length    Longueur des options.
 * @param verbosity Niveau de verbosité.
 * @param indent    Indentation pour l'affichage.
 */
void parse_ndp_options(const u_char *options, int length, int verbosity, int indent);

#endif /* NDP_H */


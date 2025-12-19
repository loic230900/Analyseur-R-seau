/**
 * Définitions pour l'analyse ICMPv6
 * 
 * Définitions de constantes et prototypes pour ICMPv6 (RFC 4443).
 * 
 */

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

/* Types MLD (Multicast Listener Discovery) - les autres dans la librairie système
rajouter au projet parce que capturer sur prise live  */
#ifndef MLD2_LISTENER_REPORT
#define MLD2_LISTENER_REPORT  143 
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

/**
 * Verbosité 1: ajoute EchoReq/EchoRep + RS/RA/NS/NA/Redirect + IP destination si fournie 
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_ip6_start    Offset du début de l'en-tête ICMPv6 (après IPv6 header).
 * @param resume              Buffer de sortie pour le résumé.
 * @param dst_ip              Chaîne de caractères de l'IP de destination (ou NULL).
 * @return                    1 en succès, 0 en échec.
*/
int icmpv6_v1_summary(const u_char *packet, int caplen, int offset_ip6_start, char *resume, const char *dst_ip);

#endif /* ICMPV6_H */
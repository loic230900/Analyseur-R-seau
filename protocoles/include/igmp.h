/**
 * Définitions pour l'analyse IGMP (Internet Group Management Protocol)
 * 
 * IGMP est utilisé pour gérer l'appartenance aux groupes multicast IPv4.
 * Protocole IP : 2. Défini dans RFC 1112 (v1), RFC 2236 (v2), RFC 3376 (v3).
 * 
 */

#ifndef IGMP_H
#define IGMP_H

#include <stdint.h>
#include <pcap.h>

/* Taille minimale de l'en-tête IGMP (v1/v2) */
#define IGMP_HDR_LEN 8

/* Types de messages IGMP */
#define IGMP_MEMBERSHIP_QUERY     0x11  /* Membership Query */
#define IGMP_V1_MEMBERSHIP_REPORT 0x12  /* IGMPv1 Membership Report */
#define IGMP_V2_MEMBERSHIP_REPORT 0x16  /* IGMPv2 Membership Report */
#define IGMP_V2_LEAVE_GROUP       0x17  /* IGMPv2 Leave Group */
#define IGMP_V3_MEMBERSHIP_REPORT 0x22  /* IGMPv3 Membership Report */

/**
 * Parse et affiche un message IGMP (verbosités 2-3)
 * @param packet    Pointeur vers le début de l'en-tête IGMP
 * @param length    Longueur restante du paquet
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Indentation pour l'affichage
 * @return          Taille de l'en-tête IGMP parsé ou 0 si erreur
 */
int parse_igmp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Retourne le nom du type IGMP
 * @param type Type IGMP
 * @return     Chaîne de caractères représentant le nom du type
 */
const char* get_igmp_type_name(uint8_t type);

/**
 * Verbosité 1: génère un résumé IGMP concis
 * @param packet         Pointeur vers le début du paquet complet
 * @param caplen         Longueur capturée totale
 * @param offset_igmp    Offset du début de l'en-tête IGMP
 * @param resume         Buffer de sortie pour le résumé
 * @param dst_ip         Adresse IP multicast destination (chaîne)
 * @return               1 en succès, 0 en échec
 */
int igmp_v1_summary(const u_char *packet, int caplen, int offset_igmp, char *resume, const char *dst_ip);

#endif /* IGMP_H */

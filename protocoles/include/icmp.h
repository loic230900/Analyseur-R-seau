/**
 * Définitions pour l'analyse ICMP 
 * 
 * Définitions de constantes et prototypes pour le parsing ICMP (RFC 792).
 * Protocole IP : 1. Utilisé pour ping, traceroute, erreurs.
 * 
 */

#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h> // Pour les constantes ICMP

// Constante de taille minimale de l'en-tête ICMP
#define ICMP_HDR_MIN_LEN 8

/**
 * Parse et affiche un en-tête ICMP
 * @param packet Pointeur vers le début de l'en-tête ICMP
 * @param length Longueur restante du paquet
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 * @return Taille de l'en-tête ICMP (8 octets minimum) ou 0 si erreur
 */
int parse_icmp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Retourne le nom du type ICMP.
 * @param type Type ICMP.
 * @return     Chaîne de caractères représentant le nom du type ICMP.
 */
const char* get_icmp_type_name(uint8_t type);

/**
 * Verbosité 1: ajoute EchoReq/EchoRep/Unreach/TimeEx/... 
 * @param packet         Pointeur vers le début du paquet complet.
 * @param caplen         Longueur capturée totale.
 * @param offset_ip_start Offset du début de l'en-tête ICMP (après IP header).
 * @param resume         Buffer de sortie pour le résumé.
 * @return               1 en succès, 0 en échec.
*/
int icmp_v1_summary(const u_char *packet, int caplen, int offset_ip_start, char *resume);

/**
 * Verbosité 1: ajoute EchoReq/EchoRep/Unreach/TimeEx/... avec IP de destination
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_icmp_start   Offset du début de l'en-tête ICMP (après IP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @param dst_ip              Chaîne de caractères de l'IP de destination (ou NULL).
 * @return                    1 en succès, 0 en échec.
 */
int icmp_v1_summary_with_ip(const u_char *packet, int caplen, int offset_icmp_start, char *resume, const char *dst_ip);

#endif /* ICMP_H */
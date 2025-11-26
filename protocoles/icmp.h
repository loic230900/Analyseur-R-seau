#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h> // Pour les constantes ICMP

/**
 * Analyse et affiche les champs de l'en-tête ICMP.
 * @param packet    Pointeur vers le début de l'en-tête ICMP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @return          Taille de l'en-tête ICMP (variable) ou 0 en cas d'erreur.
 */
int parse_icmp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Retourne le nom du type ICMP.
 * @param type Type ICMP.
 * @return     Chaîne de caractères représentant le nom du type ICMP.
 */
const char* get_icmp_type_name(uint8_t type);

/* Verbosité 1: ajoute EchoReq/EchoRep/Unreach/TimeEx/... */
int icmp_v1_summary(const u_char *packet, int caplen, int offset_ip_start, char *resume);
/* Version avec adresse IP de destination */
int icmp_v1_summary_with_ip(const u_char *packet, int caplen, int offset_icmp_start, char *resume, const char *dst_ip);

#endif /* ICMP_H */
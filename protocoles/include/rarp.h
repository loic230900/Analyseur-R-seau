/**
 * Définitions pour l'analyse RARP (Reverse ARP)
 * 
 * Définitions pour RARP (RFC 903). Résolution MAC -> IPv4.
 * 
 */

#ifndef RARP_H
#define RARP_H

#include <stdint.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

// RARP taille d'en-tête
#define RARP_HDR_LEN 28

// Types Ethernet
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP 0x8035
#endif

/**
 * Analyse et affiche les champs de l'en-tête RARP.
 * @param packet    Pointeur vers le début de l'en-tête RARP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @return          Taille de l'en-tête RARP (28 octets) ou 0 en cas d'erreur.
 */
int parse_rarp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Verbosité 1: ajoute who-is / is dans resume. offset_after_eth = position de l'en-tête RARP
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_after_eth    Offset de l'en-tête RARP (après Ethernet header).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
 */
int rarp_v1_summary(const u_char *packet, int caplen, int offset_after_eth, char *resume);

#endif /* RARP_H */


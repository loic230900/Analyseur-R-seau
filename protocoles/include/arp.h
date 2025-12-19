/**
 * Définitions pour l'analyse ARP (Address Resolution Protocol)
 * 
 * Définitions de constantes et prototypes pour le parsing ARP (RFC 826).
 * Résolution IPv4 -> MAC sur réseaux Ethernet.
 * EtherType : 0x0806
 * 
 */

#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>  // Fournit struct ether_arp système

/* ARP header size constant */
#define ARP_HDR_LEN 28

//Types Ethernet
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

/**
 * Analyse et affiche les champs de l'en-tête ARP.
 * @param packet    Pointeur vers le début de l'en-tête ARP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @return          Taille de l'en-tête ARP (28 octets) ou 0 en cas d'erreur.
 */
int parse_arp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Verbosité 1: ajoute who-is / is dans resume. offset_after_eth = position de l'en-tête ARP
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_after_eth    Offset de l'en-tête ARP (après Ethernet header).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
 */
int arp_v1_summary(const u_char *packet, int caplen, int offset_after_eth, char *resume);

#endif /* ARP_H */
#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <pcap.h>
#include <capture.h>

/**
 * Analyse et affiche les champs de l'en-tête Ethernet.
 * @param packet   Pointeur vers le début de l'en-tête Ethernet.
 * @param length   Longueur totale du paquet capturé.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent   Indentation en espaces pour l'affichage.
 * @param ethertype (sortie) EtherType extrait (en ordre hôte).
 * @return         Taille de l'en-tête Ethernet (14 octets) ou 0 en cas d'erreur.
 */
int parse_ethernet(const u_char *packet, int length, int verbosity, int indent, uint16_t *ethertype);

#endif /* ETHERNET_H */

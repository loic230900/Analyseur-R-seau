#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>
#include <pcap.h>
#include "bootp.h"
/**
 * Analyse et affiche les champs d'un message DHCP (BOOTP).
 * @param packet    Pointeur vers le début de l'en-tête DHCP (BOOTP).
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 */
void parse_dhcp(const u_char *packet, int length, int verbosity, int indent);

#endif /* DHCP_H */

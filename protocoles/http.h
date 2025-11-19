#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>


/**
 * Analyse et affiche un message HTTP(Request ou Reponse).
 * @param packet    Pointeur vers le début du payload TCP contenant HTTP.
 * @param length    Longeur du payload TCP disponible.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espace pour l'affichage.
 * @param is_request (sortie) 1 si requete HTTP, 0 si réponse si (peut etre NULL) 
 * @return          Nombre d'octets consommés (headers + body si détecté),
 *                  ou 0 si ce n'est pas du HTTP ou erreur.
 */
int parse_http(const u_char *packet, int length, int indent, int *is_request);

/**
 * Résumé verbosité 1 pour HTTP (méthode+URI ou code status).
 * @param packet           Pointeur vers le début du paquet complet.
 * @param caplen           Longueur capturée totale.
 * @param offset_tcp_payload Offset du début du payload TCP (après TCP header).
 * @param resume           Buffer de sortie pour le résumé.
 * @return                 1 en succès, 0 en échec.
 */
int http_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

#endif /* HTTP_H */
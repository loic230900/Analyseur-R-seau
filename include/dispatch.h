/**
 * Ce fichier déclare les fonctions de dispatch qui font le lien entre
 * la détection des protocoles (detection.h) et les parseurs individuels.
 * 
 */

#ifndef DISPATCH_H
#define DISPATCH_H

#include <stdint.h>
#include <pcap.h>
#include "detection.h"

// VERBOSITÉ 1 (format concis)
/**
 * Route le paquet vers la fonction *_v1_summary() appropriée pour
 * construire le résumé concis d'une ligne.
 * 
 * @param proto             Protocole détecté par detect_app_tcp()
 * @param packet            Pointeur vers le paquet complet (depuis Ethernet)
 * @param caplen            Longueur totale capturée
 * @param tcp_payload_offset Offset du début du payload TCP
 * @param resume            Buffer de sortie pour le résumé
 * @param src_port          Port source (nécessaire pour certains protocoles)
 * @param dst_port          Port destination (nécessaire pour certains protocoles)
 * @param src_ip            Adresse IP source (chaîne de caractères)
 * @param dst_ip            Adresse IP destination (chaîne de caractères)
 * 
 * @return 1 si traitement effectué, 0 si protocole non géré
 */
int process_app_tcp_v1(app_proto_tcp_t proto, const u_char *packet, int caplen, 
                       int tcp_payload_offset, char *resume,
                       uint16_t src_port, uint16_t dst_port,
                       const char *src_ip, const char *dst_ip);

/**
 * Route le paquet vers la fonction *_v1_summary() appropriée pour
 * construire le résumé concis d'une ligne.
 * 
 * @param proto             Protocole détecté par detect_app_udp()
 * @param packet            Pointeur vers le paquet complet (depuis Ethernet)
 * @param caplen            Longueur totale capturée
 * @param udp_payload_offset Offset du début du payload UDP
 * @param resume            Buffer de sortie pour le résumé
 * @param src_port          Port source
 * @param dst_port          Port destination
 * @param src_ip            Adresse IP source (chaîne de caractères)
 * @param dst_ip            Adresse IP destination (chaîne de caractères)
 * 
 * @return 1 si traitement effectué, 0 si protocole non géré
 */
int process_app_udp_v1(app_proto_udp_t proto, const u_char *packet, int caplen, 
                       int udp_payload_offset, char *resume,
                       uint16_t src_port, uint16_t dst_port,
                       const char *src_ip, const char *dst_ip);

//VERBOSITÉS 2-3 (format détaillé)
/**
 * Route le paquet vers la fonction parse_*() appropriée pour
 * un affichage détaillé multi-lignes.
 * 
 * @param proto     Protocole détecté par detect_app_tcp()
 * @param packet    Pointeur vers le payload TCP (après en-tête TCP)
 * @param length    Longueur du payload restant
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Niveau d'indentation pour l'affichage
 * @param offset    Pointeur vers l'offset courant (modifié si consommé)
 * @param src_port  Port source (nécessaire pour certains protocoles)
 * @param dst_port  Port destination (nécessaire pour certains protocoles)
 * 
 * @return Nombre d'octets consommés par le parseur
 */
int process_app_tcp_v2v3(app_proto_tcp_t proto, const u_char *packet, int length, int verbosity, int indent,
                         int *offset, uint16_t src_port, uint16_t dst_port);

/**
 * Route le paquet vers la fonction parse_*() appropriée pour
 * un affichage détaillé multi-lignes.
 * 
 * @param proto     Protocole détecté par detect_app_udp()
 * @param packet    Pointeur vers le payload UDP (après en-tête UDP)
 * @param length    Longueur du payload restant
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Niveau d'indentation pour l'affichage
 * @param offset    Pointeur vers l'offset courant (modifié si consommé)
 * 
 * @return Nombre d'octets consommés par le parseur
 */
int process_app_udp_v2v3(app_proto_udp_t proto, const u_char *packet, int length, int verbosity, int indent, int *offset);

#endif /* DISPATCH_H */

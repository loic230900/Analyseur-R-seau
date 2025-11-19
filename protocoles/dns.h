#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>

/**
 * Analyse et affiche un message DNS
 * @param packet       Pointeur vers le début du message DNS (après header UDP/TCP).
 * @param length       Longueur restante disponible (payload DNS potentielle).
 * @param verbosity    Niveau de verbosité (2 ou 3). (Le niveau 1 reste géré dans l'affichage global.)
 * @param indent       Indentation en espaces pour l'affichage.
 * @param is_tcp       1 si DNS sur TCP (longueur 2 octets en préfixe), 0 si UDP.
 * @param is_response  (sortie) 1 si QR=1 (réponse), 0 si requête.
 * @param first_qname  (sortie) Buffer pour le premier nom de question (peut être NULL si non souhaité).
 * @param qname_len    Taille du buffer first_qname.
 * @return             Nombre total d'octets consommés dans ce message DNS (incluant éventuellement le préfixe TCP),
 *                     ou 0 en cas d'erreur / troncature / format invalide.
 */
int parse_dns(const u_char *packet, int length, int verbosity, int indent,
              int is_tcp, int *is_response, char *first_qname, int qname_len);

/**
 * Décode un nom DNS à partir d'un offset.
 * @param packet        Buffer du message DNS (pointant sur le début réel du DNS, pas le paquet entier Ethernet).
 * @param length        Longueur totale disponible du message DNS (sans préfixe TCP).
 * @param base_offset   Offset de base (début du message DNS) pour interpréter les pointeurs de compression.
 * @param name_offset   Offset où commence le nom à décoder.
 * @param out           Buffer de sortie
 * @param out_len       Taille max du buffer de sortie.
 * @param consumed      (sortie) Octets consommés à partir de name_offset (ignorer après premier pointeur).
 * @return              1 en cas de succès, 0 en cas d'erreur (boucle, dépassement, format invalide).
 */
int dns_decode_name(const u_char *packet, int length, int base_offset,
                    int name_offset, char *out, int out_len, int *consumed);

/**
 * Donne une représentation textuelle d'un TYPE DNS .
 * @param type  Valeur numérique du type.
 * @return      Chaîne constante
 */
const char* dns_type_to_str(uint16_t type);

/**
 * Donne une représentation textuelle d'une CLASS DNS
 * @param klass Valeur numérique de la classe.
 * @return      Chaîne constante.
 */
const char* dns_class_to_str(uint16_t klass);

/**
 * Convertit les champs opcode et rcode en chaînes lisibles.
 */
const char* dns_opcode_to_str(uint8_t opcode);
const char* dns_rcode_to_str(uint8_t rcode);

/**
 * Renvoie l'expression BPF pour capturer tout le trafic DNS (UDP et TCP, ports 53).
 */
const char* dns_bpf_all(void);

/**
 * Résumé verbosité 1 pour DNS (Query/Resp + premier QNAME)
 * @param packet            Pointeur vers le début du paquet complet.
 * @param caplen            Longueur capturée totale.
 * @param offset_dns_payload Offset du début DNS (après UDP/TCP header).
 * @param resume            Buffer de sortie pour le résumé.
 * @param is_tcp            1 si DNS sur TCP (préfixe longueur 2 octets), 0 sinon.
 * @return                  1 en succès, 0 en échec.
 */
int dns_v1_summary(const u_char *packet, int caplen, int offset_dns_payload, char *resume, int is_tcp);

/* Constantes type */
#define DNS_TYPE_A       1
#define DNS_TYPE_NS      2
#define DNS_TYPE_CNAME   5
#define DNS_TYPE_SOA     6
#define DNS_TYPE_PTR     12
#define DNS_TYPE_MX      15
#define DNS_TYPE_TXT     16
#define DNS_TYPE_AAAA    28
#define DNS_TYPE_OPT     41

/* Classes */
#define DNS_CLASS_IN     1
#define DNS_CLASS_CH     3

/* Limites internes */
#define DNS_MAX_NAME_LEN     255
#define DNS_MAX_LABEL_LEN    63
#define DNS_MAX_POINTERS     10

#endif /* DNS_H */
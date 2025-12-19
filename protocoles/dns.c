/**

 * Analyseur de messages DNS 
 * 
 * Ce module implémente le parsing complet des messages DNS conformément aux RFCs.
 *  Ce protocol a été très casse-tête à implémenter  ....
 */

#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h> /* pour u_char */
#include <arpa/inet.h> /* inet_ntop pour affichage IP lisible */
#include "../util/safe_string.h"
#include "../util/textutils.h"

/* Fallback au cas où u_char n'est pas défini par les en-têtes système */
#ifndef UCHAR_TYPEDEF_GUARD
#define UCHAR_TYPEDEF_GUARD
typedef unsigned char u_char;
#endif

/**
 * Convertit un type d'enregistrement DNS en chaîne lisible
 * @param type Code numérique du type (ex: 1 pour A, 28 pour AAAA)
 * @return Nom du type ou "UNKNOWN" si non reconnu
 */
const char* dns_type_to_str(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_SRV: return "SRV";
        case DNS_TYPE_OPT: return "OPT";
        case DNS_TYPE_DS: return "DS";
        case DNS_TYPE_RRSIG: return "RRSIG";
        case DNS_TYPE_NSEC: return "NSEC";
        case DNS_TYPE_DNSKEY: return "DNSKEY";
        case DNS_TYPE_SVCB: return "SVCB";
        case DNS_TYPE_HTTPS: return "HTTPS";
        case DNS_TYPE_AXFR: return "AXFR";
        case DNS_TYPE_ANY: return "ANY";
        case DNS_TYPE_CAA: return "CAA";
        case 13: return "HINFO";
        case 35: return "NAPTR";
        default: return "UNKNOWN";
    }
}

/**
 * Convertit une classe DNS en chaîne lisible 
 * @param class Code numérique de la classe (ex: 1 pour IN, 3 pour CH)
 * @return Nom de la classe ou "UNKNOWN" si non reconnu
 */
const char* dns_class_to_str(uint16_t class) {
    switch (class) {
        case DNS_CLASS_IN: return "IN";
        case DNS_CLASS_CH: return "CH";
        default: return "UNKNOWN";
    }
}

/**
 * Convertit un opcode DNS en chaîne lisible
 * @param opcode Code de l'opération (0=QUERY, 1=IQUERY, 2=STATUS, etc.)
 * @return Nom de l'opcode ou "UNKNOWN" si non reconnu
 */
const char* dns_opcode_to_str(uint8_t opcode) {
    switch (opcode) {
        case 0: return "QUERY";
        case 1: return "IQUERY";
        case 2: return "STATUS";
        case 4: return "NOTIFY";
        case 5: return "UPDATE";
        default: return "UNKNOWN";
    }
}

/**
 * Convertit un code de réponse DNS (RCODE) en chaîne lisible
 * @param rcode Code de réponse (0=NOERROR, 3=NXDOMAIN, etc.)
 * @return Nom du RCODE ou "UNKNOWN" si non reconnu
 */
const char* dns_rcode_to_str(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        case 6: return "YXDOMAIN";
        case 7: return "YXRRSET";
        case 8: return "NXRRSET";
        case 9: return "NOTAUTH";
        case 10: return "NOTZONE";
        default: return "UNKNOWN";
    }
}

/* Expression BPF pour capturer tout le trafic DNS (UDP et TCP port 53) */
const char* dns_bpf_all(void) {
    return "(udp port 53 or tcp port 53)";
}

/**
 * Décode un nom de domaine DNS avec support de la compression 
 * 
 * La compression DNS permet de réduire la taille des messages en utilisant des pointeurs
 * vers des parties de noms déjà présentes dans le message. Un pointeur est identifié par
 * les 2 bits de poids fort à 1 (0xC0), les 14 bits restants indiquant l'offset du nom cible.
 * 
 * Exemple : Si "www.example.com" apparaît d'abord, puis "mail.example.com",
 * le second peut être encodé comme "mail" + pointeur_vers("example.com")
 * 
 * pour comprendre le déroulement ci dessous:
 * Algorithme :
 * 1. Lire la longueur du label (1 octet)
 * 2. Si longueur = 0 : fin du nom
 * 3. Si les 2 bits de poids fort = 11 (0xC0) : c'est un pointeur de compression
 *    - Lire les 14 bits restants comme offset absolu
 *    - Sauter à cet offset et continuer le décodage
 *    - Protection contre les boucles infinies (max DNS_MAX_POINTERS sauts)
 * 4. Sinon : c'est un label normal, copier les octets et ajouter un '.'
 * 
 * @param packet Paquet complet (base pour les pointeurs absolus)
 * @param length Longueur totale du paquet
 * @param base_offset Offset de base du message DNS (pour calcul absolu des pointeurs)
 * @param name_offset Offset du début du nom à décoder
 * @param out Buffer de sortie pour le nom décodé
 * @param out_len Taille du buffer de sortie
 * @param consumed Nombre d'octets consommés dans le message original (sans suivre les pointeurs)
 * @return 1 si succès, 0 si erreur
 */
int dns_decode_name(const u_char *packet, int length, int base_offset, int name_offset, char *out, int out_len, int *consumed) {
    int pos = name_offset;
    int out_pos = 0;
    int followed_pointer = 0;  /* Indique si on a suivi au moins un pointeur */
    int pointer_count = 0;      /* Compteur pour détecter les boucles infinies */
    *consumed = 0;

    // Boucle de décodage du nom
    while (1) {
        if (pos >= length) return 0;
        uint8_t len = packet[pos];

        /* Cas 1 : Fin de nom (longueur = 0) */
        if (len == 0) {
            if (!followed_pointer) (*consumed)++;
            if (out_pos == 0) {
                out[out_pos++] = '.';  // nom racine vide
            }
            out[out_pos] = '\0';
            return 1;
        }

        /* Cas 2 : Pointeur de compression (bits 7-6 = 11, soit 0xC0) */
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= length) return 0;
            // Extraire l'offset sur 14 bits : ((premier_octet & 0x3F) << 8) | second_octet 
            uint16_t ptr = ((len & 0x3F) << 8) | packet[pos + 1];

            if (base_offset + ptr >= length) return 0;  /* Pointeur hors limites */
            if (!followed_pointer) {
                *consumed += 2;  /* Le pointeur occupe 2 octets */
                followed_pointer = 1;
            }
            /* Protection contre les boucles infinies : limite le nombre de sauts */
            if (++pointer_count > DNS_MAX_POINTERS) return 0;
            pos = base_offset + ptr;  /* Sauter vers la cible du pointeur */
            continue;
        }

        /* Cas 3 : Label normal (bits 7-6 = 00) */
        if (len & 0xC0) return 0;  /* Bits 10 ou 01 sont réservés, format invalide */
        if (len > DNS_MAX_LABEL_LEN) return 0;  /* Label trop long (max 63 caractères) */
        if (pos + 1 + len > length) return 0;
        if (out_pos + len + 2 > out_len) return 0;

        /* Ajouter un point séparateur sauf pour le premier label */
        if (out_pos > 0) out[out_pos++] = '.';
        memcpy(out + out_pos, packet + pos + 1, len);
        out_pos += len;

        pos += len + 1;
        if (!followed_pointer) (*consumed) += len + 1;
    }
}

/**
 * Parse une question DNS et l'affiche selon la verbosité
 * 
 * @param packet Paquet complet
 * @param length Longueur du paquet
 * @param base_offset Offset de base du message DNS
 * @param offset Position de la question dans le paquet
 * @param verbosity Niveau de verbosité
 * @param indent Indentation pour l'affichage
 * @param qname_out Buffer de sortie pour le nom de domaine (peut être NULL)
 * @param qname_len Taille du buffer qname_out
 * @param bytes_consumed Nombre d'octets consommés
 * @param out_qtype Type de la question (sortie)
 * @param out_qclass Classe de la question (sortie)
 * @return 1 si succès, 0 si erreur
 */
static int parse_dns_question(const u_char *packet, int length, int base_offset, int offset, int verbosity, int indent,
                              char *qname_out, int qname_len,
                              int *bytes_consumed,
                              uint16_t *out_qtype, uint16_t *out_qclass) {
    int start = offset; // pour calculer les octets consommés
    int name_consumed;
    char qname[DNS_MAX_NAME_LEN];

    // si échec du décodage du nom
    if (!dns_decode_name(packet, length, base_offset, offset, qname, sizeof(qname), &name_consumed)) {
        return 0;
    }
    offset += name_consumed;

    if (offset + 4 > length) return 0;
    uint16_t qtype  = ntohs(*(uint16_t*)(packet + offset)); offset += 2;
    uint16_t qclass = ntohs(*(uint16_t*)(packet + offset)); offset += 2;

    if (out_qtype) *out_qtype = qtype;
    if (out_qclass) *out_qclass = qclass;

    if (verbosity >= 3) {
        printf("%*sQuestion: %s %s %s\n",
               indent, "",
               qname,
               dns_class_to_str(qclass),
               dns_type_to_str(qtype));
    }

    if (qname_out && qname_len > 0) {
        size_t n = (size_t)((qname_len - 1) > 0 ? (qname_len - 1) : 0);
        strncpy(qname_out, qname, n);
        qname_out[qname_len - 1] = '\0';
    }

    *bytes_consumed = offset - start;
    return 1;
}

/**
 * Parse un Resource Record (RR) DNS et l'affiche selon la verbosité
 * 
 * @param packet Paquet complet
 * @param length Longueur du paquet
 * @param base_offset Offset de base du message DNS
 * @param offset Position du RR dans le paquet
 * @param verbosity Niveau de verbosité
 * @param indent Indentation pour l'affichage
 * @param section_label Libellé de la section ("Answer", "Authority", "Additional")
 * @param bytes_consumed Nombre d'octets consommés
 * @return 1 si succès, 0 si erreur
 */
static int parse_dns_rr(const u_char *packet, int length, int base_offset, int offset,
                        int verbosity, int indent,const char *section_label,int *bytes_consumed) {
    
    int start = offset;
    int name_consumed;
    char name[DNS_MAX_NAME_LEN];

    if (!dns_decode_name(packet, length, base_offset, offset,
                         name, sizeof(name), &name_consumed)) {
        return 0;
    }
    offset += name_consumed; // avancer après le nom

    if (offset + 10 > length) return 0;
    uint16_t type     = ntohs(*(uint16_t*)(packet + offset)); offset += 2;  // Type d'enregistrement
    uint16_t class    = ntohs(*(uint16_t*)(packet + offset)); offset += 2; // Classe
    uint32_t ttl      = ntohl(*(uint32_t*)(packet + offset)); offset += 4;  // TTL
    uint16_t rdlength = ntohs(*(uint16_t*)(packet + offset)); offset += 2;  // Longueur des données

    // Vérification de la longueur des données
    if (offset + rdlength > length) return 0;
    int rdata_offset = offset;

    if (verbosity >= 3) {
        printf("%*s%s: %s %s %s TTL=%u ",indent, "", section_label,
            name, dns_class_to_str(class), dns_type_to_str(type),ttl);
    }

    /* Décodage des RDATA selon le type d'enregistrement */
    if (verbosity >= 3) {
        switch (type) {
            case DNS_TYPE_A:  /* Adresse IPv4 (4 octets) */
                if (rdlength == 4) {
                    const u_char *a = packet + rdata_offset;
                    printf("A -> %u.%u.%u.%u\n", a[0], a[1], a[2], a[3]);
                } else {
                    printf("A (len=%u invalid)\n", rdlength);
                }
                break;

            case DNS_TYPE_AAAA:  /* Adresse IPv6 (16 octets) */
                if (rdlength == 16) {
                    struct in6_addr addr6;
                    char ip6[INET6_ADDRSTRLEN];
                    memcpy(&addr6, packet + rdata_offset, 16);
                    if (inet_ntop(AF_INET6, &addr6, ip6, sizeof(ip6)) != NULL) {
                        printf("AAAA -> %s\n", ip6);
                    } else {
                        printf("AAAA -> (invalid address)\n");
                    }
                } else {
                    printf("AAAA (len=%u invalid)\n", rdlength);
                }
                break;

            case DNS_TYPE_NS:     /* Serveur de noms */
            case DNS_TYPE_CNAME:  /* Nom canonique (alias) */
            case DNS_TYPE_PTR: {  /* Pointeur (résolution inverse) */
                char target[DNS_MAX_NAME_LEN];
                int target_consumed;
                if (dns_decode_name(packet, length, base_offset, rdata_offset, target, sizeof(target),&target_consumed)) {
                    printf("%s -> %s\n",
                           (type == DNS_TYPE_NS ? "NS" :
                            type == DNS_TYPE_CNAME ? "CNAME" : "PTR"),
                           target);
                } else {
                    printf("Invalid name\n");
                }
                break;
            }

            case DNS_TYPE_MX:  /* Mail Exchanger (serveur de messagerie) */
                if (rdlength >= 2) {
                    uint16_t pref = ntohs(*(uint16_t*)(packet + rdata_offset));
                    char exch[DNS_MAX_NAME_LEN];
                    int exch_consumed;
                    if (dns_decode_name(packet, length, base_offset,
                                        rdata_offset + 2, exch, sizeof(exch),
                                        &exch_consumed)) {
                        printf("MX -> Pref=%u %s\n", pref, exch);
                    } else {
                        printf("MX -> Pref=%u (invalid name)\n", pref);
                    }
                } else {
                    printf("MX (len=%u invalid)\n", rdlength);
                }
                break;

            case DNS_TYPE_TXT: {  /* Texte libre */
                printf("TXT -> \"");
                int pos = rdata_offset;
                int end = rdata_offset + rdlength;
                while (pos < end) {
                    uint8_t seglen = packet[pos++];
                    if (pos + seglen > end) break;
                    for (int i = 0; i < seglen; i++) {
                        uint8_t c = packet[pos + i];
                        /* Afficher les caractères imprimables, remplacer les autres par '.' */
                        printf("%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                    pos += seglen;
                    if (pos < end) printf(" ");
                }
                printf("\"\n");
                break;
            }

            case DNS_TYPE_SOA: {  /* Start of Authority (informations de zone) */
                /* Structure : MNAME + RNAME + serial + refresh + retry + expire + minimum */
                char mname[DNS_MAX_NAME_LEN], rname[DNS_MAX_NAME_LEN];
                int c1, c2;     // consommés pour MNAME et RNAME
                int p = rdata_offset; 
                if (dns_decode_name(packet, length, base_offset, p,
                                    mname, sizeof(mname), &c1)) {
                    // avancer après MNAME
                    p += c1;         
                    if (dns_decode_name(packet, length, base_offset, p,
                                        rname, sizeof(rname), &c2)) {
                        // avancer après RNAME
                        p += c2;
                        //  Vérifier qu'il reste assez d'octets pour les 5 champs uint32_t
                        if (p + 20 <= rdata_offset + rdlength) {
                            uint32_t serial  = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t refresh = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t retry   = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t expire  = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t minimum = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            printf("SOA -> M=%s R=%s s=%u ref=%u ret=%u exp=%u min=%u\n",
                                   mname, rname, serial, refresh, retry, expire, minimum);
                        } else {
                            printf("SOA -> truncated structure\n");
                        }
                    } else {
                        printf("SOA -> invalid RNAME\n");
                    }
                } else {
                    printf("SOA -> invalid MNAME\n");
                }
                break;
            }

            case DNS_TYPE_OPT: {  /* EDNS0 pseudo-RR (RFC 6891) */
                /* EDNS0 : classe = taille max UDP, TTL = flags étendus */
                /* Le champ TTL (4 octets) contient : extended RCODE (1) | version (1) | flags (2) */
                uint8_t edns_version = (uint8_t)((ttl >> 16) & 0xFF);
                uint16_t flags = (uint16_t)(ttl & 0xFFFF);
                int do_bit = (flags >> 15) & 0x01;  /* DNSSEC OK bit */
                
                printf("OPT -> EDNS0 UDPsize=%u ver=%u DO=%d", class, edns_version, do_bit);
                
                /* Parser les options EDNS0 contenues dans RDATA */
                if (rdlength > 0) {
                    printf(" opts=");
                    int pos = rdata_offset;
                    int end = rdata_offset + rdlength;
                    int first = 1;
                    while (pos + 4 <= end) {
                        uint16_t opt_code = ntohs(*(uint16_t*)(packet + pos)); pos += 2;
                        uint16_t opt_len = ntohs(*(uint16_t*)(packet + pos)); pos += 2;
                        if (pos + opt_len > end) break;
                        
                        if (!first) printf(",");
                        first = 0;
                        
                        switch(opt_code) {
                            case 3: printf("NSID"); break;       /* Name Server ID */
                            case 8: printf("ECS"); break;        /* Client Subnet */
                            case 10: printf("Cookie"); break;    /* DNS Cookie */
                            case 15: printf("ExtErr"); break;    /* Extended Error */
                            default: printf("code%u", opt_code); break;
                        }
                        pos += opt_len;
                    }
                }
                printf("\n");
                break;
            }

            case 33: {  /* SRV - Service locator (RFC 2782) */
                if (rdlength >= 6) {
                    uint16_t priority = ntohs(*(uint16_t*)(packet + rdata_offset));
                    uint16_t weight = ntohs(*(uint16_t*)(packet + rdata_offset + 2));
                    uint16_t port = ntohs(*(uint16_t*)(packet + rdata_offset + 4));
                    char target[DNS_MAX_NAME_LEN];
                    int target_consumed;
                    if (dns_decode_name(packet, length, base_offset,
                                        rdata_offset + 6, target, sizeof(target),
                                        &target_consumed)) {
                        printf("SRV -> Pri=%u Wt=%u Port=%u Target=%s\n",
                               priority, weight, port, target);
                    } else {
                        printf("SRV -> Pri=%u Wt=%u Port=%u (invalid target)\n",
                               priority, weight, port);
                    }
                } else {
                    printf("SRV (len=%u invalid)\n", rdlength);
                }
                break;
            }

            case 257: {  /* CAA - Certification Authority Authorization (RFC 6844) */
                if (rdlength >= 2) {
                    uint8_t flags_caa = packet[rdata_offset];
                    uint8_t tag_len = packet[rdata_offset + 1];
                    if (rdata_offset + 2 + tag_len <= rdata_offset + rdlength) {
                        char tag[64] = "";
                        int tl = tag_len < 63 ? tag_len : 63;
                        memcpy(tag, packet + rdata_offset + 2, (size_t)tl);
                        tag[tl] = '\0';
                        
                        int value_offset = rdata_offset + 2 + tag_len;
                        int value_len = rdlength - 2 - tag_len;
                        printf("CAA -> Flags=%u Tag=%s Value=", flags_caa, tag);
                        for (int i = 0; i < value_len && i < 32; i++) {
                            uint8_t c = packet[value_offset + i];
                            printf("%c", (c >= 32 && c <= 126) ? c : '.');
                        }
                        if (value_len > 32) printf("...");
                        printf("\n");
                    } else {
                        printf("CAA (invalid structure)\n");
                    }
                } else {
                    printf("CAA (len=%u invalid)\n", rdlength);
                }
                break;
            }

            default: {
                /* Type non géré : détecter si les données sont du texte ASCII imprimable */
                int is_printable = 1;
                if (rdlength == 0) is_printable = 0;
                for (int i = 0; i < rdlength && is_printable; i++) {
                    uint8_t c = packet[rdata_offset + i];
                    if ((c < 32 || c > 126) && c != 9 && c != 10 && c != 13) {
                        is_printable = 0;
                    }
                }
                
                if (is_printable && rdlength > 0) {
                    printf("DATA -> ");
                    for (int i = 0; i < rdlength; i++) {
                        uint8_t c = packet[rdata_offset + i];
                        printf("%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                    printf("\n");
                } else {
                    printf("TYPE=%u RDLEN=%u", type, rdlength);
                    if (rdlength > 0) printf(" HEX=");
                    for (int i = 0; i < rdlength && i < 12; i++) {
                        printf("%02x", packet[rdata_offset + i]);
                        if (i < rdlength - 1 && i < 11) printf(" ");
                    }
                    if (rdlength > 12) printf(" ...");
                    printf("\n");
                }
                break;
            }
        }
    }

    offset += rdlength;
    *bytes_consumed = offset - start;
    return 1;
}

/**
 * Parse un message DNS complet et affiche les informations selon la verbosité
 * 
 * Gère les messages DNS sur UDP (format direct) et TCP (préfixe de 2 octets
 * indiquant la longueur du message). Parse l'en-tête, les questions et les
 * différentes sections de réponse (Answer, Authority, Additional).
 * 
 * @param packet Pointeur vers le début du message DNS
 * @param length Nombre d'octets disponibles
 * @param verbosity Niveau de verbosité (1=résumé, 2=synthétique, 3=détaillé)
 * @param indent Indentation pour l'affichage
 * @param is_tcp 1 si message sur TCP (préfixe de longueur), 0 pour UDP
 * @param is_response Pointeur de sortie : 1 si réponse, 0 si requête
 * @param first_qname Buffer de sortie pour le premier nom de domaine interrogé
 * @param qname_len Taille du buffer first_qname
 * @return Nombre d'octets consommés, 0 en cas d'erreur
 */
int parse_dns(const u_char *packet, int length, int verbosity, int indent,
              int is_tcp, int *is_response, char *first_qname, int qname_len) {
    /* Modèle de parsing : travailler sur 'msg' à partir du début du message DNS.
       Pour TCP, sauter le préfixe de longueur (2 octets) et limiter à cette longueur. */
    const u_char *msg = packet;
    int msg_len = length;
    int total_consumed = 0;

    /* Préfixe TCP : 2 octets indiquant la longueur du message DNS */
    if (is_tcp) {
        if (msg_len < 2) return 0;
        uint16_t mlen = (packet[0] << 8) | packet[1];
        if (2 + (int)mlen > msg_len) return 0;
        msg = packet + 2;
        msg_len = (int)mlen;
        total_consumed = 2;
    }

    int offset = 0;
    int base_offset = 0; /* Base pour la compression des noms (relative à 'msg') */

    /* En-tête DNS minimum : 12 octets */
    if (offset + 12 > msg_len) return 0;

    /* Extraction des champs de l'en-tête DNS */
    uint16_t id      = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t flags   = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t qdcount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t ancount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t nscount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t arcount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;

    /* Décodage des flags DNS */
    uint8_t qr     = (flags >> 15) & 0x01;  /* Query/Response : 0=requête, 1=réponse */
    uint8_t opcode = (flags >> 11) & 0x0F;  /* Type d'opération */
    uint8_t aa     = (flags >> 10) & 0x01;  /* Authoritative Answer */
    uint8_t tc     = (flags >> 9)  & 0x01;  /* Truncation */
    uint8_t rd     = (flags >> 8)  & 0x01;  /* Recursion Desired */
    uint8_t ra     = (flags >> 7)  & 0x01;  /* Recursion Available */
    uint8_t rcode  = flags & 0x0F;          /* Response Code */

    if (is_response) *is_response = qr;

    /* Verbosité 3 : affichage détaillé de l'en-tête */
    if (verbosity == 3) {
        print_indent(indent);
        printf("[L7] DNS Header:\n");
        
        print_indent(indent);
        printf("    Transaction ID: 0x%04x\n", id);
        
        print_indent(indent);
        printf("    Flags: QR=%u (%s), Opcode=%u (%s), AA=%u, TC=%u, RD=%u, RA=%u\n",
               qr, qr ? "Response" : "Request",
               opcode, dns_opcode_to_str(opcode),
               aa, tc, rd, ra);
        
        print_indent(indent);
        printf("    Response code: %u (%s)\n", rcode, dns_rcode_to_str(rcode));
        
        print_indent(indent);
        printf("    Questions: %u, Answers: %u, Authority: %u, Additional: %u\n",
               qdcount, ancount, nscount, arcount);
    }

    /* Section Questions */
    for (int i = 0; i < (int)qdcount; i++) {
        int consumed;
        uint16_t qtype_tmp = 0, qclass_tmp = 0;
        if (!parse_dns_question(msg, msg_len,
                                 base_offset, offset,
                                 verbosity, indent + 4,
                                 (i == 0 ? first_qname : NULL), qname_len,
                                 &consumed, &qtype_tmp, &qclass_tmp)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;
    }

    /* Section Answers (réponses) */
    for (int i = 0; i < (int)ancount; i++) {
        if (i == 0 && verbosity >= 3) {
            print_indent(indent);
            printf("    -- Answers --\n");
        }
        int consumed;
        if (!parse_dns_rr(msg, msg_len,
                          base_offset, offset,
                          verbosity, indent + 4,
                          "Answer", &consumed)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;
    }

    /* Section Authority (serveurs de noms faisant autorité) */
    for (int i = 0; i < (int)nscount; i++) {
        if (i == 0 && verbosity >= 3) {
            print_indent(indent);
            printf("    -- Authority --\n");
        }
        int consumed;
        if (!parse_dns_rr(msg, msg_len,
                          base_offset, offset,
                          verbosity, indent + 4,
                          "Authority", &consumed)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;
    }

    /* Section Additional (enregistrements additionnels, incluant EDNS0) */
    for (int i = 0; i < (int)arcount; i++) {
        if (i == 0 && verbosity >= 3) {
            print_indent(indent);
            printf("    -- Additional --\n");
        }
        int consumed;
        if (!parse_dns_rr(msg, msg_len,
                          base_offset, offset,
                          verbosity, indent + 4,
                          "Additional", &consumed)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;
    }

    /* Verbosité 2 : résumé synthétique avec type de requête et première réponse */
    if (verbosity == 2) {
        print_indent(indent);
        const char *qname = (first_qname && first_qname[0]) ? first_qname : "(none)";
        
        /* Extraire le type de la première question et la première réponse si disponible */
        char output[512] = "";
        if(qdcount > 0) {
            char tmp_qname[DNS_MAX_NAME_LEN];
            int tmp_consumed;
            if(dns_decode_name(msg, msg_len, base_offset, base_offset + 12,
                              tmp_qname, sizeof(tmp_qname), &tmp_consumed)) {
                int qtype_offset = base_offset + 12 + tmp_consumed;
                if(qtype_offset + 2 <= msg_len) {
                    uint16_t qtype = (uint16_t)((msg[12 + tmp_consumed] << 8) | msg[12 + tmp_consumed + 1]);
                    const char *qtype_name = dns_type_to_str(qtype);
                    
                    /* Si c'est une réponse avec des enregistrements, extraire la première valeur */
                    if(qr && ancount > 0) {
                        int ans_offset = base_offset + 12 + tmp_consumed + 4;
                        char ans_name[DNS_MAX_NAME_LEN];
                        int ans_consumed;
                        
                        if(dns_decode_name(msg, msg_len, base_offset, ans_offset,
                                          ans_name, sizeof(ans_name), &ans_consumed)) {
                            int ans_type_offset = ans_offset + ans_consumed;
                            if(ans_type_offset + 10 <= msg_len) {
                                uint16_t ans_type = (msg[ans_type_offset - base_offset] << 8) | 
                                                   msg[ans_type_offset - base_offset + 1];
                                uint16_t ans_rdlen = (msg[ans_type_offset - base_offset + 8] << 8) | 
                                                    msg[ans_type_offset - base_offset + 9];
                                int rdata_offset = ans_type_offset + 10;
                                
                                /* Afficher la valeur selon le type d'enregistrement */
                                if(ans_type == DNS_TYPE_A && ans_rdlen == 4 && 
                                   rdata_offset - base_offset + 4 <= msg_len) {
                                    snprintf(output, sizeof(output), "DNS: Response %s (%s) -> %u.%u.%u.%u\n",
                                            qname, qtype_name,
                                            msg[rdata_offset - base_offset],
                                            msg[rdata_offset - base_offset + 1],
                                            msg[rdata_offset - base_offset + 2],
                                            msg[rdata_offset - base_offset + 3]);
                                } else if(ans_type == DNS_TYPE_AAAA && ans_rdlen == 16 && 
                                         rdata_offset - base_offset + 16 <= msg_len) {
                                    char ipv6[INET6_ADDRSTRLEN];
                                    inet_ntop(AF_INET6, (const void*)&msg[rdata_offset - base_offset], 
                                             ipv6, sizeof(ipv6));
                                    snprintf(output, sizeof(output), "DNS: Response %s (%s) -> %s\n",
                                            qname, qtype_name, ipv6);
                                } else if(ans_type == DNS_TYPE_CNAME && ans_rdlen > 0) {
                                    char cname[DNS_MAX_NAME_LEN];
                                    int cname_consumed;
                                    if(dns_decode_name(msg, msg_len, base_offset, rdata_offset,
                                                      cname, sizeof(cname), &cname_consumed)) {
                                        snprintf(output, sizeof(output), "DNS: Response %s (%s) -> %s\n",
                                                qname, qtype_name, cname);
                                    }
                                } else {
                                    snprintf(output, sizeof(output), "DNS: Response %s (%s) [AN=%u]\n",
                                            qname, qtype_name, ancount);
                                }
                            }
                        }
                        
                        if(output[0] == '\0') {
                            snprintf(output, sizeof(output), "DNS: Response %s (%s) [AN=%u]\n",
                                    qname, qtype_name, ancount);
                        }
                    } else {
                        /* Requête ou réponse sans enregistrement de réponse */
                        snprintf(output, sizeof(output), "DNS: %s %s (%s)\n",
                                qr ? "Réponse" : "Requête", qname, qtype_name);
                    }
                }
            }
        }
        
        if(output[0] != '\0') {
            printf("%s", output);
        } else {
            printf("DNS: %s %s [AN=%u]\n", qr ? "Response" : "Query", qname, ancount);
        }
    }

    return total_consumed + offset;
}

int dns_v1_summary(const u_char *packet, int caplen, int offset_dns_payload, char *resume, int is_tcp){
    /* Gérer préfixe TCP (2 octets longueur) */
    if(is_tcp) {
        if(caplen < offset_dns_payload + 2) return 0;
        offset_dns_payload += 2;
    }
    
    if(caplen < offset_dns_payload + 12) return 0;
    const u_char *dns = packet + offset_dns_payload;
    uint16_t flags = (dns[2] << 8) | dns[3];
    int qr = (flags >> 15) & 0x1;
    uint16_t ancount = (dns[6] << 8) | dns[7];
    
    /* Utiliser dns_decode_name pour gérer compression correctement */
    char qname[DNS_MAX_NAME_LEN];
    int consumed;
    if(dns_decode_name(packet, caplen, offset_dns_payload, offset_dns_payload + 12,
                       qname, sizeof(qname), &consumed)) {
        if(qname[0] == 0 || qname[0] == '.') strncpy(qname, "(root)", sizeof(qname) - 1);
        
        // Get query type
        int qtype_offset = offset_dns_payload + 12 + consumed;
        if(qtype_offset + 4 <= caplen) {
            uint16_t qtype = (dns[12 + consumed] << 8) | dns[12 + consumed + 1];
            const char* type_str = dns_type_to_str(qtype);
            
            if(qr) {
                // Response - show domain name, answer type, and resolved value
                int found_answer = 0;
                if(ancount > 0) {
                    // Try to read answer records and find matching query type
                    int ans_offset = offset_dns_payload + 12 + consumed + 4;
                    
                    // Loop through answer records to find matching query type
                    for(int ans_idx = 0; ans_idx < ancount && !found_answer && ans_offset < caplen - 10; ans_idx++) {
                        char ans_name[DNS_MAX_NAME_LEN];
                        int ans_consumed;
                        if(dns_decode_name(packet, caplen, offset_dns_payload, ans_offset,
                                          ans_name, sizeof(ans_name), &ans_consumed)) {
                            // After answer name: type(2) + class(2) + ttl(4) + rdlen(2) + rdata
                            int ans_type_offset = ans_offset + ans_consumed;
                            if(ans_type_offset + 10 <= caplen) {
                                uint16_t ans_type = (packet[ans_type_offset] << 8) | packet[ans_type_offset + 1];
                                uint16_t ans_rdlen = (packet[ans_type_offset + 8] << 8) | packet[ans_type_offset + 9];
                                const char* ans_type_str = dns_type_to_str(ans_type);
                                int rdata_offset = ans_type_offset + 10;
                                
                                // Check if this answer matches the query type
                                if(ans_type == qtype) {
                                    // Extract and display answer data for the queried type
                                    char answer_data[512] = "";
                                    
                                    if(ans_type == DNS_TYPE_A && ans_rdlen == 4 && rdata_offset + 4 <= caplen) {
                                        // IPv4 address
                                        snprintf(answer_data, sizeof(answer_data), " -> %u.%u.%u.%u",
                                                packet[rdata_offset], packet[rdata_offset + 1],
                                                packet[rdata_offset + 2], packet[rdata_offset + 3]);
                                        found_answer = 1;
                                    } else if(ans_type == DNS_TYPE_AAAA && ans_rdlen == 16 && rdata_offset + 16 <= caplen) {
                                        // IPv6 address - show in compact form
                                        char ipv6[INET6_ADDRSTRLEN];
                                        inet_ntop(AF_INET6, (const void*)&packet[rdata_offset], ipv6, sizeof(ipv6));
                                        snprintf(answer_data, sizeof(answer_data), " -> %s", ipv6);
                                        found_answer = 1;
                                    } else if(ans_type == DNS_TYPE_CNAME && ans_rdlen > 0 && rdata_offset + ans_rdlen <= caplen) {
                                        // CNAME - decode the name
                                        char cname[DNS_MAX_NAME_LEN];
                                        int cname_consumed;
                                        if(dns_decode_name(packet, caplen, offset_dns_payload, rdata_offset,
                                                          cname, sizeof(cname), &cname_consumed)) {
                                            snprintf(answer_data, sizeof(answer_data), " -> %s", cname);
                                            found_answer = 1;
                                        }
                                    } else if(ans_type == DNS_TYPE_MX && ans_rdlen > 0 && rdata_offset + ans_rdlen <= caplen) {
                                        // MX record - preference(2) + mail_exchange_name
                                        if(rdata_offset + 2 <= caplen) {
                                            char mx_name[DNS_MAX_NAME_LEN];
                                            int mx_consumed;
                                            if(dns_decode_name(packet, caplen, offset_dns_payload, rdata_offset + 2,
                                                              mx_name, sizeof(mx_name), &mx_consumed)) {
                                                snprintf(answer_data, sizeof(answer_data), " -> %s", mx_name);
                                                found_answer = 1;
                                            }
                                        }
                                    } else if(ans_type == DNS_TYPE_NS && ans_rdlen > 0 && rdata_offset + ans_rdlen <= caplen) {
                                        // NS record - nameserver name
                                        char ns_name[DNS_MAX_NAME_LEN];
                                        int ns_consumed;
                                        if(dns_decode_name(packet, caplen, offset_dns_payload, rdata_offset,
                                                          ns_name, sizeof(ns_name), &ns_consumed)) {
                                            snprintf(answer_data, sizeof(answer_data), " -> %s", ns_name);
                                            found_answer = 1;
                                        }
                                    } else if(ans_type == DNS_TYPE_TXT && ans_rdlen > 0 && rdata_offset + ans_rdlen <= caplen) {
                                        // TXT record - show first 50 chars
                                        char txt[51] = "";
                                        int txt_len = (ans_rdlen > 50) ? 50 : ans_rdlen;
                                        for(int i = 0; i < txt_len; i++) {
                                            unsigned char uc = packet[rdata_offset + i];
                                            txt[i] = (uc >= 32 && uc < 127) ? (char)uc : '.';
                                        }
                                        txt[txt_len] = 0;
                                        snprintf(answer_data, sizeof(answer_data), " -> %s", txt);
                                        found_answer = 1;
                                    } else if(ans_rdlen > 0) {
                                        // Generic: just mark answer found
                                        found_answer = 1;
                                    }
                                    
                                    // Toujours essayer d'afficher la réponse si on a trouvé un answer
                                    if(found_answer) {
                                        // Construction du résumé de réponse DNS
                                        safe_strcat(resume, " Resp: ", RESUME_BUFFER_SIZE);
                                        safe_strcat(resume, qname, RESUME_BUFFER_SIZE);
                                        safe_strcat(resume, " (", RESUME_BUFFER_SIZE);
                                        safe_strcat(resume, ans_type_str, RESUME_BUFFER_SIZE);
                                        safe_strcat(resume, ")", RESUME_BUFFER_SIZE);
                                        safe_strcat(resume, answer_data, RESUME_BUFFER_SIZE);
                                        return 1;
                                    }
                                }
                                
                                // Move to next answer record
                                ans_offset = rdata_offset + ans_rdlen;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
                // Si aucune réponse trouvée correspondant au type de la requête, afficher avec indication
                if(!found_answer && can_append(resume, qname, RESUME_BUFFER_SIZE)) {
                    safe_strcat(resume, " Resp: ", RESUME_BUFFER_SIZE);
                    safe_strcat(resume, qname, RESUME_BUFFER_SIZE);
                    safe_strcat(resume, " (", RESUME_BUFFER_SIZE);
                    safe_strcat(resume, type_str, RESUME_BUFFER_SIZE);
                    safe_strcat(resume, ") -> No record", RESUME_BUFFER_SIZE);
                }
            } else {
                // Requête - afficher le nom de domaine et le type de requête
                if(can_append(resume, qname, RESUME_BUFFER_SIZE) && 
                   can_append(resume, type_str, RESUME_BUFFER_SIZE)) {
                    safe_strcat(resume, " Query: ", RESUME_BUFFER_SIZE);
                    safe_strcat(resume, qname, RESUME_BUFFER_SIZE);
                    safe_strcat(resume, " (", RESUME_BUFFER_SIZE);
                    safe_strcat(resume, type_str, RESUME_BUFFER_SIZE);
                    safe_strcat(resume, ")", RESUME_BUFFER_SIZE);
                }
            }
        } else {
            // Fallback si le type ne peut pas être lu
            const char *qr_str = qr ? " Resp" : " Query";
            if(can_append(resume, qname, RESUME_BUFFER_SIZE)) {
                safe_strcat(resume, qr_str, RESUME_BUFFER_SIZE);
                safe_strcat(resume, " ", RESUME_BUFFER_SIZE);
                safe_strcat(resume, qname, RESUME_BUFFER_SIZE);
            } else {
                safe_strcat(resume, qr_str, RESUME_BUFFER_SIZE);
            }
        }
    } else {
        // Fallback si le décodage du nom échoue
        safe_strcat(resume, qr ? " Resp" : " Query", RESUME_BUFFER_SIZE);
    }
    return 1;
}
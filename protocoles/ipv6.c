/**
 * @file ipv6.c
 * @brief Analyseur de paquets IPv6 (couche 3 - Réseau)
 * 
 * Ce module implémente le parsing des paquets IPv6 conformément à la RFC 8200.
 * L'en-tête IPv6 fait 40 octets fixes + en-têtes d'extension variables.
 * 
 * EtherType : 0x86DD
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "ipv6.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include "../util/textutils.h"

/* Constantes pour les en-têtes d'extension IPv6 */
#define IPV6_EXT_HOP_BY_HOP   0   /* Hop-by-Hop Options */
#define IPV6_EXT_ROUTING     43   /* Routing Header */
#define IPV6_EXT_FRAGMENT    44   /* Fragment Header */
#define IPV6_EXT_ESP         50   /* Encapsulating Security Payload */
#define IPV6_EXT_AH          51   /* Authentication Header */
#define IPV6_NO_NEXT_HEADER  59   /* No Next Header */
#define IPV6_EXT_DEST_OPT    60   /* Destination Options */
#define IPV6_EXT_MOBILITY   135   /* Mobility Header */

/**
 * @brief Retourne le nom lisible d'un type d'en-tête d'extension IPv6
 * @param ext_type Type d'en-tête d'extension
 * @return Chaîne de caractères représentant le type, ou NULL si inconnu
 */
static const char* get_ext_header_name(uint8_t ext_type) {
    switch(ext_type) {
        case IPV6_EXT_HOP_BY_HOP: return "Hop-by-Hop Options";
        case IPV6_EXT_ROUTING:    return "Routing";
        case IPV6_EXT_FRAGMENT:   return "Fragment";
        case IPV6_EXT_ESP:        return "ESP";
        case IPV6_EXT_AH:         return "Authentication Header";
        case IPV6_NO_NEXT_HEADER: return "No Next Header";
        case IPV6_EXT_DEST_OPT:   return "Destination Options";
        case IPV6_EXT_MOBILITY:   return "Mobility";
        default:                  return NULL;
    }
}

/**
 * @brief Vérifie si un numéro de protocole est un en-tête d'extension IPv6
 */
static int is_extension_header(uint8_t next_hdr) {
    switch(next_hdr) {
        case 0:   /* Hop-by-Hop Options */
        case 43:  /* Routing */
        case 44:  /* Fragment */
        case 50:  /* ESP */
        case 51:  /* AH */
        case 60:  /* Destination Options */
        case 135: /* Mobility */
            return 1;
        default:
            return 0;
    }
}

/**
 * @brief Parse un en-tête IPv6 et ses en-têtes d'extension
 * @param packet Pointeur vers le début de l'en-tête IPv6
 * @param length Nombre d'octets disponibles dans le buffer
 * @param verbosity Niveau de verbosité (1=résumé, 2=synthétique, 3=détaillé)
 * @param indent Indentation pour l'affichage (espaces)
 * @param next_hdr Pointeur de sortie pour le protocole final après les extensions
 * @return Nombre d'octets consommés (en-tête + extensions), 0 en cas d'erreur
 */
int parse_ipv6(const u_char *packet, int length, int verbosity, int indent, uint8_t *next_hdr){
    if(length < (int)sizeof(struct ip6_hdr)) {
        fprintf(stderr, "IPv6: Packet too short for IPv6 header (need %zu, got %d)\n",
                sizeof(struct ip6_hdr), length);
        return 0;
    }
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)packet;
    *next_hdr = ip6->ip6_nxt;
    uint32_t v_tfl = ntohl(ip6->ip6_flow); /* Version + Traffic Class + Flow Label */
    uint16_t payload_len = ntohs(ip6->ip6_plen); /* Longueur de la charge utile */

    /* Conversion des adresses IPv6 en notation hexadécimale standard */
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, sizeof(dst_ip));

    /* Verbosité 2 : affichage synthétique sur une ligne */
    if(verbosity == 2){
        print_indent(indent);
        printf("IPv6: %s -> %s [next=%u hop_limit=%u]\n", src_ip, dst_ip, ip6->ip6_nxt, ip6->ip6_hlim);
    }
    /* Verbosité 3 : affichage détaillé avec indicateur de couche OSI */
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L3] IPv6 Header:\n");
        
        print_indent(indent);
        printf("      Version: %u, TC: 0x%02x, Flow: 0x%05x\n",(v_tfl >> 28) & 0xF, (v_tfl >> 20) & 0xFF, v_tfl & 0xFFFFF);
        
        print_indent(indent);
        printf("      Payload Len: %u, Next Hdr: %u, Hop Limit: %u\n",payload_len, ip6->ip6_nxt, ip6->ip6_hlim);
        
        print_indent(indent);
        printf("      Source IP:    %s", src_ip);
        /* Identification des adresses spéciales IPv6 */
        if(strcmp(src_ip, "::") == 0 || strcmp(src_ip, "::1") == 0) printf(" [UNSPECIFIED/LOOPBACK]");
        else if(strncmp(src_ip, "ff", 2) == 0) printf(" [MULTICAST]");
        else if(strncmp(src_ip, "fe80:", 5) == 0) printf(" [LINK-LOCAL]");
        else if(strncmp(src_ip, "fc00:", 5) == 0 || strncmp(src_ip, "fd00:", 5) == 0) printf(" [UNIQUE-LOCAL]");
        printf("\n");
        
        print_indent(indent);
        printf("      Dest IP:      %s", dst_ip);
        if(strcmp(dst_ip, "::") == 0 || strcmp(dst_ip, "::1") == 0) printf(" [UNSPECIFIED/LOOPBACK]");
        else if(strncmp(dst_ip, "ff", 2) == 0) printf(" [MULTICAST]");
        else if(strncmp(dst_ip, "fe80:", 5) == 0) printf(" [LINK-LOCAL]");
        else if(strncmp(dst_ip, "fc00:", 5) == 0 || strncmp(dst_ip, "fd00:", 5) == 0) printf(" [UNIQUE-LOCAL]");
        printf("\n");
    }
    
    /**
     * Parsing de la chaîne d'en-têtes d'extension IPv6 (RFC 8200)
     * 
     * IPv6 utilise un système d'en-têtes chaînés pour les options et fonctionnalités
     * avancées. Chaque en-tête contient un champ "Next Header" indiquant le type
     * d'en-tête suivant, formant ainsi une chaîne.
     * 
     * Structure générale :
     * [En-tête IPv6 fixe] -> [Ext Header 1] -> [Ext Header 2] -> ... -> [Couche Transport]
     * 
     * Types d'en-têtes d'extension (ordre RFC 8200) :
     * - Hop-by-Hop Options (0) : Options examinées par chaque routeur
     * - Destination Options (60) : Options pour le destinataire final
     * - Routing (43) : Spécification du chemin de routage
     * - Fragment (44) : Fragmentation des paquets trop grands (TOUJOURS 8 octets)
     * - Authentication Header (51) : Authentification IPsec
     * - ESP (50) : Chiffrement IPsec
     * - Mobility (135) : Support de la mobilité IPv6
     * - No Next Header (59) : Indique la fin de la chaîne
     * 
     * Format des en-têtes (sauf Fragment) :
     * Octet 0 : Next Header (type du prochain en-tête)
     * Octet 1 : Hdr Ext Len (longueur = (valeur + 1) × 8 octets)
     * Octets suivants : Données spécifiques à l'en-tête
     * 
     * L'en-tête Fragment est spécial : taille fixe de 8 octets, pas de champ longueur.
     */
    int offset = sizeof(struct ip6_hdr);
    uint8_t current_hdr = ip6->ip6_nxt;
    int ext_count = 0;
    const int MAX_EXT_HEADERS = 10; /* Protection contre les boucles infinies */
    
    /* Parcourir la chaîne d'en-têtes d'extension */
    while(is_extension_header(current_hdr) && offset < length && ext_count < MAX_EXT_HEADERS) {
        if(offset + 2 > length) {
            fprintf(stderr, "IPv6: Extension header truncated at offset %d\n", offset);
            return offset;
        }
        
        const u_char *ext_hdr = packet + offset;
        uint8_t next = ext_hdr[0];  /* Champ Next Header (toujours en octet 0) */
        
        /* Cas spécial : No Next Header - fin de la chaîne */
        if(current_hdr == IPV6_NO_NEXT_HEADER) {
            *next_hdr = current_hdr;
            if(verbosity == 3) {
                print_indent(indent + 2);
                printf("Extension Header: No Next Header (end of chain)\n");
            }
            return offset;
        }
        
        /* Cas spécial : Fragment Header - taille fixe de 8 octets (pas de champ longueur) */
        if(current_hdr == IPV6_EXT_FRAGMENT) {
            if(offset + 8 > length) {
                fprintf(stderr, "IPv6: Fragment header truncated\n");
                return offset;
            }
            if(verbosity == 3) {
                print_indent(indent + 2);
                printf("Extension Header: Fragment (8 bytes)\n");
            }
            offset += 8;
        } else {
            /* Cas général : longueur calculée depuis le champ Hdr Ext Len (octet 1) */
            /* Formule : Longueur = (hdr[1] + 1) × 8 octets */
            uint8_t hdr_len = ext_hdr[1];
            int ext_size = (hdr_len + 1) * 8;
            
            if(offset + ext_size > length) {
                fprintf(stderr, "IPv6: Extension header truncated (need %d, got %d)\n",
                        ext_size, length - offset);
                return offset;
            }
            
            if(verbosity == 3) {
                const char *name = get_ext_header_name(current_hdr);
                print_indent(indent + 2);
                if(name) {
                    printf("Extension Header: %s (%d bytes)\n", name, ext_size);
                } else {
                    printf("Extension Header: Type %u (%d bytes)\n", current_hdr, ext_size);
                }
            }
            offset += ext_size;
        }
        
        current_hdr = next;  /* Passer à l'en-tête suivant dans la chaîne */
        ext_count++;
    }
    
    if(ext_count >= MAX_EXT_HEADERS) {
        fprintf(stderr, "IPv6: Too many extension headers (possible loop detected)\n");
    }
    
    /* Mettre à jour next_hdr avec le protocole final (TCP, UDP, ICMPv6, etc.) */
    *next_hdr = current_hdr;
    
    return offset; /* Retourner l'offset total incluant tous les en-têtes d'extension */
}
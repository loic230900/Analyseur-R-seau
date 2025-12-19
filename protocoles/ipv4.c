/**
 * @file ipv4.c
 * @brief Analyseur de paquets IPv4 (couche 3 - Réseau)
 * 
 * Ce module implémente le parsing des paquets IPv4 conformément à la RFC 791.
 * L'en-tête IPv4 fait 20-60 octets (IHL * 4 octets).
 * 
 * EtherType : 0x0800
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "ipv4.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "../util/textutils.h"

/**
 * @brief Vérifie si une adresse IPv4 est privée (RFC 1918)
 */
static int is_private_ipv4(const char *ip) {
    /* 10.0.0.0/8 */
    if(strncmp(ip, "10.", 3) == 0) return 1;
    /* 172.16.0.0/12 */
    if(strncmp(ip, "172.", 4) == 0) {
        int second_octet;
        if(sscanf(ip + 4, "%d", &second_octet) == 1 && second_octet >= 16 && second_octet <= 31)
            return 1;
    }
    /* 192.168.0.0/16 */
    if(strncmp(ip, "192.168.", 8) == 0) return 1;
    return 0;
}

/**
 * @brief Parse un en-tête IPv4 et affiche les informations selon la verbosité
 * @param packet Pointeur vers le début de l'en-tête IPv4
 * @param length Nombre d'octets disponibles dans le buffer
 * @param verbosity Niveau de verbosité (1=résumé, 2=synthétique, 3=détaillé)
 * @param indent Indentation pour l'affichage (espaces)
 * @param protocol Pointeur de sortie pour le numéro de protocole de couche 4
 * @return Nombre d'octets consommés (taille de l'en-tête), 0 en cas d'erreur
 */
int parse_ipv4(const u_char *packet, int length, int verbosity, int indent, uint8_t *protocol) {
    if (length < (int)sizeof(struct iphdr)) {
        fprintf(stderr, "IPv4: Packet too short for IPv4 header\n");
        return 0;
    }

    const struct iphdr *ip = (const struct iphdr *)packet;
    int ihl = ip->ihl * 4; /* Longueur de l'en-tête IP en octets (IHL * 4) */
    if (length < ihl) {
        fprintf(stderr, "IPv4: Packet too short for complete header (need %d, got %d)\n", ihl, length);
        return 0;
    }
    
    /* Vérifier la fragmentation AVANT de définir le protocole */
    uint16_t frag_off = ntohs(ip->frag_off);
    uint16_t offset = frag_off & 0x1FFF;  /* Offset du fragment (13 bits inférieurs) */
    
    /* Si ce n'est pas le premier fragment, l'en-tête de couche transport n'est pas présent */
    if(offset > 0) {
        *protocol = 0; /* Signal : pas de couche transport à parser */
        if(verbosity >= 2) {
            print_indent(indent);
            printf("IPv4: Fragment (offset=%u), no transport layer in this fragment\n", offset);
        }
        return ihl; /* Retour précoce, ignorer le parsing L4 */
    }
    
    *protocol = ip->protocol;

    /* Conversion des adresses IP binaires en notation décimale pointée */
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr = { .s_addr = ip->saddr };
    struct in_addr dst_addr = { .s_addr = ip->daddr };
    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    /* Verbosité 2 : affichage synthétique sur une ligne */
    if (verbosity == 2) {
        print_indent(indent);
        printf("IPv4: %s -> %s [proto=%u ttl=%u]\n", src_ip, dst_ip, ip->protocol, ip->ttl);
    }
    /* Verbosité 3 : affichage détaillé avec indicateur de couche OSI */
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L3] IPv4 Header:\n");

        print_indent(indent);
        printf("      Version: %u, IHL: %u (%d bytes), TOS: 0x%02x\n", ip->version, ip->ihl, ihl, ip->tos);

        print_indent(indent);
        printf("      Total Length: %u, ID: 0x%04x\n", ntohs(ip->tot_len), ntohs(ip->id));

        uint16_t frag_off = ntohs(ip->frag_off);
        uint8_t flags = (frag_off >> 13) & 0x7;
        uint16_t offset = frag_off & 0x1FFF;

        /* Décodage des flags de fragmentation */
        print_indent(indent);
        printf("      Flags: 0x%x", flags);
        if(flags & 0x2) printf(" DF"); /* Don't Fragment - Ne pas fragmenter */
        if(flags & 0x4) printf(" MF"); /* More Fragments - Autres fragments à suivre */
        if(flags == 0) printf(" (none)");
        printf(", Fragment Offset: %u", offset);
        if(offset > 0 || (flags & 0x4)) printf(" [FRAGMENTED]");
        printf("\n");

        print_indent(indent);
        printf("      TTL: %u, Protocol: %u, Checksum: 0x%04x\n", ip->ttl, ip->protocol, ntohs(ip->check));

        print_indent(indent);
        printf("      Source IP:    %s", src_ip);
        /* Identification des adresses spéciales */
        if(strcmp(src_ip, "0.0.0.0") == 0) printf(" [UNSPECIFIED]");
        else if(strcmp(src_ip, "255.255.255.255") == 0) printf(" [BROADCAST]");
        else if(strncmp(src_ip, "127.", 4) == 0) printf(" [LOOPBACK]");
        else if(strncmp(src_ip, "224.", 4) == 0 || strncmp(src_ip, "239.", 4) == 0) printf(" [MULTICAST]");
        else if(strncmp(src_ip, "169.254.", 8) == 0) printf(" [LINK-LOCAL]");
        else if(is_private_ipv4(src_ip)) printf(" [PRIVATE]");
        printf("\n");

        print_indent(indent);
        printf("      Dest IP:      %s", dst_ip);
        if(strcmp(dst_ip, "0.0.0.0") == 0) printf(" [UNSPECIFIED]");
        else if(strcmp(dst_ip, "255.255.255.255") == 0) printf(" [BROADCAST]");
        else if(strncmp(dst_ip, "127.", 4) == 0) printf(" [LOOPBACK]");
        else if(strncmp(dst_ip, "224.", 4) == 0 || strncmp(dst_ip, "239.", 4) == 0) printf(" [MULTICAST]");
        else if(strncmp(dst_ip, "169.254.", 8) == 0) printf(" [LINK-LOCAL]");
        else if(is_private_ipv4(dst_ip)) printf(" [PRIVATE]");
        printf("\n");
        if (ihl > 20) {
            int options_len = ihl - 20;
            print_indent(indent);
            printf("      Options: %d bytes\n", options_len);
            
            /* Parser les options IPv4 courantes (RFC 791) */
            if(length >= ihl && options_len > 0) {
                const u_char *options = packet + 20;
                int offset = 0;
                int parsed_any = 0;
                
                while(offset < options_len) {
                    uint8_t opt_type = options[offset];
                    
                    if(opt_type == 0) { /* Fin de liste d'options */
                        break;
                    }
                    if(opt_type == 1) { /* NOP - No Operation */
                        offset++;
                        continue;
                    }
                    
                    if(offset + 1 >= options_len) break;
                    uint8_t opt_len = options[offset + 1];
                    if(opt_len < 2 || offset + opt_len > options_len) break;
                    
                    switch(opt_type) {
                        case 7: /* Record Route - Enregistrement du chemin */
                            if(opt_len >= 3) {
                                uint8_t ptr = options[offset + 2];
                                print_indent(indent);
                                printf("        Record Route: ptr=%u\n", ptr);
                                parsed_any = 1;
                            }
                            break;
                        case 9: /* Strict Source Route - Routage source strict */
                            if(opt_len >= 3) {
                                uint8_t ptr = options[offset + 2];
                                print_indent(indent);
                                printf("        Strict Source Route: ptr=%u\n", ptr);
                                parsed_any = 1;
                            }
                            break;
                        case 10: /* Loose Source Route - Routage source lâche */
                            if(opt_len >= 3) {
                                uint8_t ptr = options[offset + 2];
                                print_indent(indent);
                                printf("        Loose Source Route: ptr=%u\n", ptr);
                                parsed_any = 1;
                            }
                            break;
                        case 20: /* Router Alert - Alerte routeur (RFC 2113) */
                            if(opt_len == 4) {
                                uint16_t alert = ntohs(*(const uint16_t *)(options + offset + 2));
                                print_indent(indent);
                                printf("        Router Alert: 0x%04x\n", alert);
                                parsed_any = 1;
                            }
                            break;
                        default:
                            /* Option non gérée - affichage hexadécimal */
                            if(opt_len <= 8 && !parsed_any) {
                                print_indent(indent);
                                printf("        Option %u: ", opt_type);
                                for(int i = 0; i < opt_len && i < 8; i++) {
                                    printf("%02x ", options[offset + i]);
                                }
                                printf("\n");
                            }
                            break;
                    }
                    
                    offset += opt_len;
                }
                
                /* Affichage hexadécimal des données d'options restantes */
                if(!parsed_any || offset < options_len) {
                    print_indent(indent);
                    printf("        ");
                    int start = parsed_any ? offset : 0;
                    for(int i = start; i < options_len; i++) {
                        printf("%02x ", options[i]);
                        if((i - start + 1) % 16 == 0 && i < options_len - 1) {
                            printf("\n");
                            print_indent(indent);
                            printf("        ");
                        }
                    }
                    if(start < options_len) printf("\n");
                }
            }
        }
    }
    return ihl;
}
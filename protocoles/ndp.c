/**

Analyseur de messages NDP (couche 3 - Réseau, sous-ensemble ICMPv6)
 * 
 * Ce module implémente le parsing du Neighbor Discovery Protocol conformément
 * à la RFC 4861. NDP est essentiel au fonctionnement d'IPv6 et remplace
 * ARP/RARP/ICMP Router Discovery d'IPv4.
 * 
 * Encapsulation : IPv6 -> ICMPv6 -> NDP (types 133-137)
 * 
 * Types de messages NDP :
 * - Type 133 : Router Solicitation (RS)
 *   Client demande aux routeurs de s'annoncer
 * 
 * - Type 134 : Router Advertisement (RA)
 *   Routeur annonce sa présence et les préfixes réseau
 *   Inclut : Hop Limit, Flags (M/O), Router Lifetime, Reachable Time
 *   Options : Prefix Information, MTU, Source Link-Layer Address
 * 
 * - Type 135 : Neighbor Solicitation (NS)
 *   Résolution d'adresse IPv6 -> MAC (équivalent ARP Request)
 *   Détection d'adresse dupliquée (DAD)
 * 
 * - Type 136 : Neighbor Advertisement (NA)
 *   Réponse à NS avec adresse MAC (équivalent ARP Reply)
 *   Flags : Router (R), Solicited (S), Override (O)
 * 
 * - Type 137 : Redirect
 *   Routeur indique un meilleur chemin
 * 
 * Options NDP analysées :
 * - Type 1 : Source Link-Layer Address
 * - Type 2 : Target Link-Layer Address
 * - Type 3 : Prefix Information
 * - Type 5 : MTU
 * 
 */

#include "ndp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/textutils.h"

/* ============================================================================
 * Analyse complète d'un message NDP
 * ============================================================================ */
int parse_ndp(const u_char *packet, int length, int verbosity, int indent) {
    if(length < (int)sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "NDP: Packet too short for NDP\n");
        return 0;
    }

    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)packet;
    uint8_t type = icmp6->icmp6_type;

    int consumed = 0;

    switch(type) {
        case ND_NEIGHBOR_SOLICIT: {
            if(length < (int)sizeof(struct nd_neighbor_solicit)) {
                fprintf(stderr, "NDP: Packet too short for Neighbor Solicitation\n");
                return 0;
            }
            const struct nd_neighbor_solicit *ns = 
                (const struct nd_neighbor_solicit *)packet;
            
            char target_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ns->nd_ns_target), target_ip, sizeof(target_ip));

            if(verbosity == 2) {
                print_indent(indent);
                printf("NDP: Neighbor Solicitation - Who has %s?\n", target_ip);
            } else if(verbosity == 3) {
                print_indent(indent);
                printf("[L4] NDP Neighbor Solicitation:\n");
                print_indent(indent);
                printf("      Target Address: %s\n", target_ip);
            }
            
            consumed = sizeof(struct nd_neighbor_solicit);
            
            // Analyse des options
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
            
            // Retourner la longueur totale (header + options)
            return length;
            break;
        }

        case ND_NEIGHBOR_ADVERT: {
            if(length < (int)sizeof(struct nd_neighbor_advert)) {
                fprintf(stderr, "NDP: Packet too short for Neighbor Advertisement\n");
                return 0;
            }
            const struct nd_neighbor_advert *na = 
                (const struct nd_neighbor_advert *)packet;
            
            char target_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(na->nd_na_target), target_ip, sizeof(target_ip));

            // Extraction des flags (R, S, O)
            uint32_t flags = ntohl(na->nd_na_hdr.icmp6_dataun.icmp6_un_data32[0]);
            int r_flag = (flags & 0x80000000) ? 1 : 0;
            int s_flag = (flags & 0x40000000) ? 1 : 0;
            int o_flag = (flags & 0x20000000) ? 1 : 0;

            if(verbosity == 2) {
                print_indent(indent);
                printf("NDP: Neighbor Advertisement - %s (R=%d,S=%d,O=%d)\n", 
                       target_ip, r_flag, s_flag, o_flag);
            } else if(verbosity == 3) {
                print_indent(indent);
                printf("[L4] NDP Neighbor Advertisement:\n");
                print_indent(indent);
                printf("      Target Address: %s\n", target_ip);
                print_indent(indent);
                printf("      Flags: Router=%d, Solicited=%d, Override=%d\n", 
                       r_flag, s_flag, o_flag);
            }
            
            consumed = sizeof(struct nd_neighbor_advert);
            
            // Analyse des options
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
            
            // Retourner la longueur totale (header + options)
            return length;
            break;
        }

        case ND_ROUTER_SOLICIT: {
            if(verbosity == 2) {
                print_indent(indent);
                printf("NDP: Router Solicitation\n");
            } else if(verbosity == 3) {
                print_indent(indent);
                printf("[L4] NDP Router Solicitation\n");
            }
            consumed = sizeof(struct nd_router_solicit);
            
            // Analyse des options si présentes
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
            return length;
            break;
        }

        case ND_ROUTER_ADVERT: {
            if(length < (int)sizeof(struct nd_router_advert)) {
                fprintf(stderr, "NDP: Packet too short for Router Advertisement\n");
                return 0;
            }
            const struct nd_router_advert *ra = 
                (const struct nd_router_advert *)packet;

            if(verbosity == 2) {
                print_indent(indent);
                printf("NDP: Router Advertisement\n");
            } else if(verbosity == 3) {
                print_indent(indent);
                printf("[L4] NDP Router Advertisement\n");
                print_indent(indent);
                printf("Hop Limit: %u\n", ra->nd_ra_curhoplimit);
                print_indent(indent);
                printf("Router Lifetime: %u seconds\n", ntohs(ra->nd_ra_router_lifetime));
            }
            consumed = sizeof(struct nd_router_advert);
            
            // Analyse des options (Prefix Information, MTU, etc.)
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
            return length;
            break;
        }

        default:
            consumed = sizeof(struct icmp6_hdr);
            break;
    }

    return consumed;
}

// Analyse des options TLV des messages NDP
void parse_ndp_options(const u_char *options, int length, int verbosity, int indent) {
    int offset = 0;
    
    while(offset + 2 <= length) {
        uint8_t opt_type = options[offset];
        uint8_t opt_len = options[offset + 1];  // Longueur en unités de 8 octets
        
        if(opt_len == 0 || offset + opt_len * 8 > length) {
            break;  // Option invalide ou incomplète
        }

        switch(opt_type) {
            case ND_OPT_SOURCE_LINKADDR:
            case ND_OPT_TARGET_LINKADDR: {
                if(opt_len * 8 >= 8) {  // Doit avoir au moins 8 octets
                    const uint8_t *mac = &options[offset + 2];
                    char mac_str[18];
                    snprintf(mac_str, sizeof(mac_str), 
                             "%02x:%02x:%02x:%02x:%02x:%02x",
                             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    
                    if(verbosity == 2) {
                        print_indent(indent);
                        printf("  Option: %s Link-Layer = %s\n", 
                               opt_type == ND_OPT_SOURCE_LINKADDR ? "Source" : "Target",
                               mac_str);
                    } else if(verbosity == 3) {
                        print_indent(indent);
                        printf("Option %s Link-Layer Address:\n", 
                               opt_type == ND_OPT_SOURCE_LINKADDR ? "Source" : "Target");
                        print_indent(indent + 2);
                        printf("MAC: %s\n", mac_str);
                    }
                }
                break;
            }

            case ND_OPT_PREFIX_INFORMATION: {
                // Parser prefix information (32 bytes)
                if(opt_len * 8 >= 32) {
                    uint8_t prefix_len = options[offset + 2];
                    uint8_t flags_pi = options[offset + 3];
                    int on_link = (flags_pi & 0x80) ? 1 : 0;
                    int autonomous = (flags_pi & 0x40) ? 1 : 0;
                    uint32_t valid_lifetime = ntohl(*(const uint32_t *)&options[offset + 4]);
                    uint32_t preferred_lifetime = ntohl(*(const uint32_t *)&options[offset + 8]);
                    
                    char prefix_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &options[offset + 16], prefix_str, sizeof(prefix_str));
                    
                    if(verbosity == 2) {
                        print_indent(indent);
                        printf("  Option: Prefix %s/%u (L=%d,A=%d)\n", 
                               prefix_str, prefix_len, on_link, autonomous);
                    } else if(verbosity == 3) {
                        print_indent(indent);
                        printf("    Option Prefix Information:\n");
                        print_indent(indent + 2);
                        printf("Prefix: %s/%u\n", prefix_str, prefix_len);
                        print_indent(indent + 2);
                        printf("Flags: On-Link=%d, Autonomous=%d\n", on_link, autonomous);
                        print_indent(indent + 2);
                        printf("Valid Lifetime: %u sec, Preferred: %u sec\n", 
                               valid_lifetime, preferred_lifetime);
                    }
                } else {
                    if(verbosity >= 2) {
                        print_indent(indent);
                        printf("  Option: Prefix Information (truncated)\n");
                    }
                }
                break;
            }

            case ND_OPT_MTU: {
                if(opt_len * 8 >= 8) {
                    uint32_t mtu = (options[offset+4] << 24) | 
                                   (options[offset+5] << 16) |
                                   (options[offset+6] << 8) | 
                                   options[offset+7];
                    if(verbosity >= 2) {
                        print_indent(indent);
                        printf("Option: MTU = %u\n", mtu);
                    }
                }
                break;
            }

            default:
                if(verbosity == 3) {
                    print_indent(indent);
                    printf("Option: Type %u (not parsed)\n", opt_type);
                }
                break;
        }
        
        offset += opt_len * 8;
    }
}


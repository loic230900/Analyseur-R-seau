#include "ndp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// Analyse complète d'un message NDP
int parse_ndp(const u_char *packet, int length, int verbosity, int indent) {
    if(length < (int)sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "Erreur: Paquet trop court pour NDP.\n");
        return 0;
    }

    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)packet;
    uint8_t type = icmp6->icmp6_type;

    int consumed = 0;

    switch(type) {
        case ND_NEIGHBOR_SOLICIT: {
            if(length < (int)sizeof(struct nd_neighbor_solicit)) {
                fprintf(stderr, "Paquet trop court pour NS\n");
                return 0;
            }
            const struct nd_neighbor_solicit *ns = 
                (const struct nd_neighbor_solicit *)packet;
            
            char target_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ns->nd_ns_target), target_ip, sizeof(target_ip));

            if(verbosity == 2) {
                printf("NDP: Neighbor Solicitation - Who has %s?\n", target_ip);
            } else if(verbosity == 3) {
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Message: Neighbor Solicitation\n");
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Target Address: %s\n", target_ip);
            }
            
            consumed = sizeof(struct nd_neighbor_solicit);
            
            // Analyse des options
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
            break;
        }

        case ND_NEIGHBOR_ADVERT: {
            if(length < (int)sizeof(struct nd_neighbor_advert)) {
                fprintf(stderr, "Paquet trop court pour NA\n");
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
                printf("NDP: Neighbor Advertisement - %s (R=%d,S=%d,O=%d)\n", 
                       target_ip, r_flag, s_flag, o_flag);
            } else if(verbosity == 3) {
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Message: Neighbor Advertisement\n");
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Target Address: %s\n", target_ip);
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Flags: Router=%d, Solicited=%d, Override=%d\n", 
                       r_flag, s_flag, o_flag);
            }
            
            consumed = sizeof(struct nd_neighbor_advert);
            
            // Analyse des options
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
            break;
        }

        case ND_ROUTER_SOLICIT: {
            if(verbosity == 2) {
                printf("NDP: Router Solicitation\n");
            } else if(verbosity == 3) {
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Message: Router Solicitation\n");
            }
            consumed = sizeof(struct nd_router_solicit);
            
            // Analyse des options si présentes
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
            break;
        }

        case ND_ROUTER_ADVERT: {
            if(length < (int)sizeof(struct nd_router_advert)) {
                fprintf(stderr, "Paquet trop court pour RA\n");
                return 0;
            }
            const struct nd_router_advert *ra = 
                (const struct nd_router_advert *)packet;

            if(verbosity == 2) {
                printf("NDP: Router Advertisement\n");
            } else if(verbosity == 3) {
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Message: Router Advertisement\n");
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Hop Limit: %u\n", ra->nd_ra_curhoplimit);
                for(int i = 0; i < indent; i++) printf(" ");
                printf("Router Lifetime: %u seconds\n", ntohs(ra->nd_ra_router_lifetime));
            }
            consumed = sizeof(struct nd_router_advert);
            
            // Analyse des options (Prefix Information, MTU, etc.)
            if(verbosity >= 2 && consumed < length) {
                parse_ndp_options(packet + consumed, length - consumed, 
                                 verbosity, indent);
            }
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
                        printf("  Option: %s Link-Layer = %s\n", 
                               opt_type == ND_OPT_SOURCE_LINKADDR ? "Source" : "Target",
                               mac_str);
                    } else if(verbosity == 3) {
                        for(int i = 0; i < indent; i++) printf(" ");
                        printf("Option %s Link-Layer Address:\n", 
                               opt_type == ND_OPT_SOURCE_LINKADDR ? "Source" : "Target");
                        for(int i = 0; i < indent+2; i++) printf(" ");
                        printf("MAC: %s\n", mac_str);
                    }
                }
                break;
            }

            case ND_OPT_PREFIX_INFORMATION: {
                // Parser prefix information (32 bytes)
                if(verbosity >= 2) {
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("Option: Prefix Information\n");
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
                        for(int i = 0; i < indent; i++) printf(" ");
                        printf("Option: MTU = %u\n", mtu);
                    }
                }
                break;
            }

            default:
                if(verbosity == 3) {
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("Option: Type %u (non analysé)\n", opt_type);
                }
                break;
        }
        
        offset += opt_len * 8;
    }
}


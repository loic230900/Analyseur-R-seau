/**
 * Analyseur NDP - Neighbor Discovery Protocol (RFC 4861)
 * 
 * Sous-protocole d'ICMPv6 pour la découverte des voisins IPv6.
 */

#include "ndp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/textutils.h"

/**
 * Convertit une adresse MAC en chaîne formatée
 * @param mac Pointeur vers les 6 octets de l'adresse MAC
 * @param out Buffer de sortie pour la chaîne formatée
 * @param len Taille du buffer de sortie
 */
static void mac_to_str(const uint8_t *mac, char *out, size_t len) {
    snprintf(out, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * Affiche l'adresse cible pour NS/NA (factorise le code commun)
 * @param verbosity Niveau de verbosité
 * @param indent Indentation pour l'affichage
 * @param msg_type Type de message NDP (ex: "Neighbor Solicitation")
 * @param target_ip Adresse IPv6 cible
 * @param extra Chaîne supplémentaire à afficher
 */
static void print_target(int verbosity, int indent, const char *msg_type, const char *target_ip, const char *extra) {
    print_indent(indent);
    if(verbosity == 2)
        printf("NDP: %s - %s%s\n", msg_type, target_ip, extra ? extra : "");
    else
        printf("[L4] NDP %s:\n", msg_type);
    
    if(verbosity == 3) {
        print_indent(indent);
        printf("      Adresse cible: %s\n", target_ip);
    }
}

/**
 * Parse les options TLV des messages NDP
 * @param options Pointeur vers le début des options
 * @param length Longueur totale des options en octets
 * @param verbosity Niveau de verbosité
 * @param indent Indentation pour l'affichage
 * @return void
 */
void parse_ndp_options(const u_char *options, int length, int verbosity, int indent) {
    int off = 0;
    
    while(off + 2 <= length) {
        uint8_t type = options[off];
        uint8_t len = options[off + 1];  /* Longueur en unités de 8 octets */
        int opt_bytes = len * 8;
        
        if(len == 0 || off + opt_bytes > length) break;

        switch(type) {
            /* Options Source/Target Link-Layer Address */
            case ND_OPT_SOURCE_LINKADDR:
            case ND_OPT_TARGET_LINKADDR:
                if(opt_bytes >= 8) {
                    char mac[18];
                    mac_to_str(&options[off + 2], mac, sizeof(mac));
                    const char *which = (type == ND_OPT_SOURCE_LINKADDR) ? "Source" : "Target";
                    print_indent(indent);
                    if(verbosity == 2)
                        printf("  Option: %s Link-Layer = %s\n", which, mac);
                    else {
                        printf("      Option %s Link-Layer: %s\n", which, mac);
                    }
                }
                break;

            /* Option Prefix Information (32 octets) */
            case ND_OPT_PREFIX_INFORMATION:
                if(opt_bytes >= 32) {
                    uint8_t prefix_len = options[off + 2];
                    uint8_t flags = options[off + 3];
                    uint32_t valid = ntohl(*(const uint32_t *)&options[off + 4]);
                    uint32_t pref = ntohl(*(const uint32_t *)&options[off + 8]);
                    char prefix[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &options[off + 16], prefix, sizeof(prefix));
                    
                    print_indent(indent);
                    if(verbosity == 2)
                        printf("  Option: Prefix %s/%u (L=%d,A=%d)\n",
                               prefix, prefix_len, (flags >> 7) & 1, (flags >> 6) & 1);
                    else {
                        printf("      Option Prefix: %s/%u\n", prefix, prefix_len);
                        print_indent(indent);
                        printf("        On-Link=%d, Autonomous=%d, Valid=%us, Preferred=%us\n",
                               (flags >> 7) & 1, (flags >> 6) & 1, valid, pref);
                    }
                }
                break;

            /* Option MTU */
            case ND_OPT_MTU:
                if(opt_bytes >= 8) {
                    uint32_t mtu = ntohl(*(const uint32_t *)&options[off + 4]);
                    print_indent(indent);
                    printf("      Option MTU: %u\n", mtu);
                }
                break;

            default:
                if(verbosity == 3) {
                    print_indent(indent);
                    printf("      Option type %u (%d octets, non parsée)\n", type, opt_bytes);
                }
        }
        off += opt_bytes;
    }
}

// Parse et affiche un message NDP

int parse_ndp(const u_char *packet, int length, int verbosity, int indent) {
    if(length < (int)sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "NDP: Paquet trop court\n");
        return 0;
    }

    uint8_t type = ((const struct icmp6_hdr *)packet)->icmp6_type;
    int hdr_size = 0;
    
    switch(type) {
        /* Neighbor Solicitation (type 135) */
        case ND_NEIGHBOR_SOLICIT: {
            hdr_size = (int)sizeof(struct nd_neighbor_solicit);
            if(length < hdr_size) return 0;
            
            char target[INET6_ADDRSTRLEN];
            const struct nd_neighbor_solicit *ns = (const struct nd_neighbor_solicit *)packet;
            inet_ntop(AF_INET6, &ns->nd_ns_target, target, sizeof(target));
            
            print_target(verbosity, indent, "Neighbor Solicitation", target, NULL);
            break;
        }

        /* Neighbor Advertisement (type 136)*/
        case ND_NEIGHBOR_ADVERT: {
            hdr_size = (int)sizeof(struct nd_neighbor_advert);
            if(length < hdr_size) return 0;
            
            const struct nd_neighbor_advert *na = (const struct nd_neighbor_advert *)packet;
            char target[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &na->nd_na_target, target, sizeof(target));
            
            /* Extraction des flags R/S/O */
            uint32_t flags = ntohl(na->nd_na_hdr.icmp6_dataun.icmp6_un_data32[0]);
            char extra[32];
            snprintf(extra, sizeof(extra), " (R=%d,S=%d,O=%d)",
                     (flags >> 31) & 1, (flags >> 30) & 1, (flags >> 29) & 1);
            
            print_target(verbosity, indent, "Neighbor Advertisement", target, 
                         verbosity == 2 ? extra : NULL);
            
            if(verbosity == 3) {
                print_indent(indent);
                printf("      Flags: Router=%d, Solicited=%d, Override=%d\n",
                       (flags >> 31) & 1, (flags >> 30) & 1, (flags >> 29) & 1);
            }
            break;
        }

        /* Router Solicitation (type 133) */
        case ND_ROUTER_SOLICIT:
            hdr_size = (int)sizeof(struct nd_router_solicit);
            print_indent(indent);
            printf(verbosity == 2 ? "NDP: Router Solicitation\n" : "[L4] NDP Router Solicitation\n");
            break;

        /* Router Advertisement (type 134)*/
        case ND_ROUTER_ADVERT: {
            hdr_size = (int)sizeof(struct nd_router_advert);
            if(length < hdr_size) return 0;
            
            const struct nd_router_advert *ra = (const struct nd_router_advert *)packet;
            print_indent(indent);
            
            if(verbosity == 2)
                printf("NDP: Router Advertisement (lifetime=%us)\n", ntohs(ra->nd_ra_router_lifetime));
            else {
                printf("[L4] NDP Router Advertisement:\n");
                print_indent(indent);
                printf("      Hop Limit: %u, Lifetime: %us\n",
                       ra->nd_ra_curhoplimit, ntohs(ra->nd_ra_router_lifetime));
            }
            break;
        }

        default:
            hdr_size = (int)sizeof(struct icmp6_hdr);
    }

    /* Parser les options si présentes */
    if(verbosity >= 2 && hdr_size < length)
        parse_ndp_options(packet + hdr_size, length - hdr_size, verbosity, indent);

    return length;
}

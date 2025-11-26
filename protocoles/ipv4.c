#include "ipv4.h"
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>   // struct iphdr on Linux
#include <arpa/inet.h>


int parse_ipv4(const u_char *packet, int length, int verbosity, int indent, uint8_t *protocol) {
    if (length < (int)sizeof(struct iphdr)) {
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête IPv4.\n");
        return 0;
    }

    const struct iphdr *ip = (const struct iphdr *)packet;
    int ihl = ip->ihl * 4; // longueur de l'en-tête IP en octets
    if (length < ihl) {
        fprintf(stderr, "Erreur: Paquet trop court pour contenir l'en-tête IPv4 complet.\n");
        return 0;
    }
    *protocol = ip->protocol;

    // conversion des adresses IP en texte
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr = { .s_addr = ip->saddr };
    struct in_addr dst_addr = { .s_addr = ip->daddr };
    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    // verbosite 2 ligne synthethique
    if (verbosity == 2) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("IPv4: src=%s, dst=%s, proto=%u, ttl=%u\n", src_ip, dst_ip, ip->protocol, ip->ttl);
    }
    // verbosite 3 detaillee
    else if (verbosity == 3) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("IP:\n");

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Version: %u, IHL: %u (%d bytes), TOS: 0x%02x\n", ip->version, ip->ihl, ihl, ip->tos);

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Total Length: %u, Identification: 0x%04x\n", ntohs(ip->tot_len), ntohs(ip->id));

        uint16_t frag_off = ntohs(ip->frag_off);
        uint8_t flags = (frag_off >> 13) & 0x7; // Reserved, DF, MF
        uint16_t offset = frag_off & 0x1FFF;

        // Décodage des flags
        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Flags: 0x%x", flags);
        if(flags & 0x2) printf(" DF"); // Don't Fragment
        if(flags & 0x4) printf(" MF"); // More Fragments
        if(flags == 0) printf(" (none)");
        printf(", Fragment Offset: %u", offset);
        if(offset > 0 || (flags & 0x4)) printf(" [FRAGMENTED]");
        printf("\n");

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("TTL: %u, Protocol: %u, Checksum: 0x%04x\n", ip->ttl, ip->protocol, ntohs(ip->check));

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Source IP: %s", src_ip);
        // Identifier les adresses spéciales
        if(strcmp(src_ip, "0.0.0.0") == 0) printf(" [UNSPECIFIED]");
        else if(strcmp(src_ip, "255.255.255.255") == 0) printf(" [BROADCAST]");
        else if(strncmp(src_ip, "127.", 4) == 0) printf(" [LOOPBACK]");
        else if(strncmp(src_ip, "224.", 4) == 0 || strncmp(src_ip, "239.", 4) == 0) printf(" [MULTICAST]");
        else if(strncmp(src_ip, "169.254.", 8) == 0) printf(" [LINK-LOCAL]");
        else if(strncmp(src_ip, "10.", 3) == 0 || strncmp(src_ip, "192.168.", 8) == 0 || strncmp(src_ip, "172.16.", 7) == 0) printf(" [PRIVATE]");
        printf("\n");

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Destination IP: %s", dst_ip);
        if(strcmp(dst_ip, "0.0.0.0") == 0) printf(" [UNSPECIFIED]");
        else if(strcmp(dst_ip, "255.255.255.255") == 0) printf(" [BROADCAST]");
        else if(strncmp(dst_ip, "127.", 4) == 0) printf(" [LOOPBACK]");
        else if(strncmp(dst_ip, "224.", 4) == 0 || strncmp(dst_ip, "239.", 4) == 0) printf(" [MULTICAST]");
        else if(strncmp(dst_ip, "169.254.", 8) == 0) printf(" [LINK-LOCAL]");
        else if(strncmp(dst_ip, "10.", 3) == 0 || strncmp(dst_ip, "192.168.", 8) == 0 || strncmp(dst_ip, "172.16.", 7) == 0) printf(" [PRIVATE]");
        printf("\n");
        if (ihl > 20) {
            int options_len = ihl - 20;
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Options: %d bytes\n", options_len);
            
            // Parser les options IPv4 courantes
            if(length >= ihl && options_len > 0) {
                const u_char *options = packet + 20;  // 20 = taille fixe en-tête IPv4
                int offset = 0;
                int parsed_any = 0;
                
                while(offset < options_len) {
                    uint8_t opt_type = options[offset];
                    
                    if(opt_type == 0) { // End of Option List
                        break;
                    }
                    if(opt_type == 1) { // No-Operation (NOP)
                        offset++;
                        continue;
                    }
                    
                    if(offset + 1 >= options_len) break;
                    uint8_t opt_len = options[offset + 1];
                    if(opt_len < 2 || offset + opt_len > options_len) break;
                    
                    switch(opt_type) {
                        case 7: // Record Route
                            if(opt_len >= 3) {
                                uint8_t ptr = options[offset + 2];
                                for(int i = 0; i < indent + 2; i++) printf(" ");
                                printf("  Record Route: pointer=%u\n", ptr);
                                parsed_any = 1;
                            }
                            break;
                        case 9: // Strict Source Route
                            if(opt_len >= 3) {
                                uint8_t ptr = options[offset + 2];
                                for(int i = 0; i < indent + 2; i++) printf(" ");
                                printf("  Strict Source Route: pointer=%u\n", ptr);
                                parsed_any = 1;
                            }
                            break;
                        case 10: // Loose Source Route
                            if(opt_len >= 3) {
                                uint8_t ptr = options[offset + 2];
                                for(int i = 0; i < indent + 2; i++) printf(" ");
                                printf("  Loose Source Route: pointer=%u\n", ptr);
                                parsed_any = 1;
                            }
                            break;
                        case 20: // Router Alert
                            if(opt_len == 4) {
                                uint16_t alert = ntohs(*(const uint16_t *)(options + offset + 2));
                                for(int i = 0; i < indent + 2; i++) printf(" ");
                                printf("  Router Alert: 0x%04x\n", alert);
                                parsed_any = 1;
                            }
                            break;
                        default:
                            // Option non gérée: afficher en hexdump seulement si petite
                            if(opt_len <= 8 && !parsed_any) {
                                for(int i = 0; i < indent + 2; i++) printf(" ");
                                printf("  Option %u: ", opt_type);
                                for(int i = 0; i < opt_len && i < 8; i++) {
                                    printf("%02x ", options[offset + i]);
                                }
                                printf("\n");
                            }
                            break;
                    }
                    
                    offset += opt_len;
                }
                
                // Si aucune option n'a été parsée ou s'il reste des données, afficher en hexdump
                if(!parsed_any || offset < options_len) {
                    for(int i = 0; i < indent + 2; i++) printf(" ");
                    printf("  ");
                    int start = parsed_any ? offset : 0;
                    for(int i = start; i < options_len; i++) {
                        printf("%02x ", options[i]);
                        if((i - start + 1) % 16 == 0 && i < options_len - 1) {
                            printf("\n");
                            for(int j = 0; j < indent + 2; j++) printf(" ");
                            printf("  ");
                        }
                    }
                    if(start < options_len) printf("\n");
                }
            }
        }
    }
    return ihl;
}
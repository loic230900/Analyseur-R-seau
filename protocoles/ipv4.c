/**
 * Ce module implémente le parsing des paquets IPv4 conformément à la RFC 791.
 * L'en-tête IPv4 fait 20-60 octets (IHL * 4 octets).
 * 
 * EtherType : 0x0800
 */

#include "../include/ipv4.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "../util/textutils.h"

/**
 * Détermine le type d'adresse IPv4 (privée, publique, spéciale)
 * @param ip Chaîne de caractères représentant l'adresse IPv4
 * @return Chaîne décrivant le type d'adresse, ou NULL si publique
 */
static const char* get_ipv4_tag(const char *ip) {
    if(strcmp(ip, "0.0.0.0") == 0) return "UNSPECIFIED";
    if(strcmp(ip, "255.255.255.255") == 0) return "BROADCAST";
    if(strncmp(ip, "127.", 4) == 0) return "LOOPBACK";
    if(strncmp(ip, "224.", 4) == 0 || strncmp(ip, "239.", 4) == 0) return "MULTICAST";
    if(strncmp(ip, "169.254.", 8) == 0) return "LINK-LOCAL";
    /* Adresses privées RFC 1918 */
    if(strncmp(ip, "10.", 3) == 0) return "PRIVATE";
    if(strncmp(ip, "192.168.", 8) == 0) return "PRIVATE";
    if(strncmp(ip, "172.", 4) == 0) {
        int oct; 
        if(sscanf(ip + 4, "%d", &oct) == 1 && oct >= 16 && oct <= 31) return "PRIVATE";
    }
    return NULL;
}

/**
 * Affiche une adresse IP avec son tag descriptif
 * @param indent Indentation en espaces
 * @param label Label à afficher avant l'adresse (ex: "Source", "Destination")
 * @param ip Chaîne de caractères représentant l'adresse IPv4
 */
static void print_ip_with_tag(int indent, const char *label, const char *ip) {
    const char *tag = get_ipv4_tag(ip);
    print_indent(indent);
    printf("      %s: %s%s%s%s\n", label, ip, tag ? " [" : "", tag ? tag : "", tag ? "]" : "");
}

/**
 * Parse les options IPv4 (verbosité 3 uniquement)
 * @param options Pointeur vers le début des options
 * @param len Longueur des options en octets
 * @param indent Indentation pour l'affichage
 * @return void
 */
static void parse_ipv4_options(const u_char *options, int len, int indent) {
    int off = 0;
    while(off < len) {
        uint8_t type = options[off];
        if(type == 0) break;           /* Fin de liste */
        if(type == 1) { off++; continue; } /* NOP */
        
        if(off + 1 >= len) break;
        uint8_t opt_len = options[off + 1];
        if(opt_len < 2 || off + opt_len > len) break;
        
        print_indent(indent);
        switch(type) {
            case 7:  printf("        Record Route: ptr=%u\n", options[off + 2]); break;
            case 9:  printf("        Strict Source Route: ptr=%u\n", options[off + 2]); break;
            case 10: printf("        Loose Source Route: ptr=%u\n", options[off + 2]); break;
            case 20: /* Router Alert RFC 2113 */
                if(opt_len == 4)
                    printf("        Router Alert: 0x%04x\n", ntohs(*(const uint16_t*)(options + off + 2)));
                break;
            default: /* Option inconnue - hexdump compact */
                printf("        Option %u:", type);
                for(int i = 0; i < opt_len && i < 8; i++) printf(" %02x", options[off + i]);
                printf("\n");
        }
        off += opt_len;
    }
}

// Parse et affiche un en-tête IPv4

int parse_ipv4(const u_char *packet, int length, int verbosity, int indent, uint8_t *protocol) {
    if(length < (int)sizeof(struct iphdr)) {
        fprintf(stderr, "IPv4: Paquet trop court\n");
        return 0;
    }

    const struct iphdr *ip = (const struct iphdr *)packet;
    int ihl = ip->ihl * 4;
    if(length < ihl) {
        fprintf(stderr, "IPv4: En-tête tronqué (besoin %d, reçu %d)\n", ihl, length);
        return 0;
    }
    
    /* Vérifier la fragmentation */
    uint16_t frag_off = ntohs(ip->frag_off);
    uint16_t offset = frag_off & 0x1FFF;
    
    if(offset > 0) {
        *protocol = 0; /* Pas de couche transport dans ce fragment */
        if(verbosity >= 2) {
            print_indent(indent);
            printf("IPv4: Fragment (offset=%u)\n", offset);
        }
        return ihl;
    }
    
    *protocol = ip->protocol;

    /* Conversion des adresses */
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

    if(verbosity == 2) {
        print_indent(indent);
        printf("IPv4: %s -> %s [proto=%u ttl=%u]\n", src_ip, dst_ip, ip->protocol, ip->ttl);
    }
    else if(verbosity == 3) {
        uint8_t flags = (frag_off >> 13) & 0x7;
        
        print_indent(indent);
        printf("[L3] IPv4 Header:\n");
        print_indent(indent);
        printf("      Version: %u, IHL: %u (%d bytes), TOS: 0x%02x\n", ip->version, ip->ihl, ihl, ip->tos);
        print_indent(indent);
        printf("      Total Length: %u, ID: 0x%04x\n", ntohs(ip->tot_len), ntohs(ip->id));
        print_indent(indent);
        printf("      Flags: 0x%x%s%s, Fragment Offset: %u%s\n",
               flags, (flags & 0x2) ? " DF" : "", (flags & 0x4) ? " MF" : "",
               offset, (offset > 0 || (flags & 0x4)) ? " [FRAGMENTED]" : "");
        print_indent(indent);
        printf("      TTL: %u, Protocol: %u, Checksum: 0x%04x\n", ip->ttl, ip->protocol, ntohs(ip->check));
        
        print_ip_with_tag(indent, "Source IP   ", src_ip);
        print_ip_with_tag(indent, "Dest IP     ", dst_ip);
        
        /* Options IPv4 si présentes */
        if(ihl > 20) {
            print_indent(indent);
            printf("      Options: %d bytes\n", ihl - 20);
            parse_ipv4_options(packet + 20, ihl - 20, indent);
        }
    }
    return ihl;
}

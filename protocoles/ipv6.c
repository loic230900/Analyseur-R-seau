/**
 * Implémente le parsing IPv6 conformément à la RFC 8200.
 * En-tête fixe de 40 octets + en-têtes d'extension variables.
 * EtherType : 0x86DD
 */

#include "ipv6.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include "../util/textutils.h"

/* Types d'en-têtes d'extension IPv6 */
static const struct { uint8_t type; const char *name; } ext_headers[] = {
    {0,   "Hop-by-Hop Options"}, {43,  "Routing"}, {44,  "Fragment"},
    {50,  "ESP"}, {51,  "Authentication Header"}, {59,  "No Next Header"},
    {60,  "Destination Options"}, {135, "Mobility"}, {0, NULL}
};

/**
 * Retourne le nom d'un en-tête d'extension, ou NULL si inconnu
 * @param type Numéro de l'en-tête d'extension
 */
static const char* get_ext_header_name(uint8_t type) {
    for(int i = 0; ext_headers[i].name; i++)
        if(ext_headers[i].type == type) return ext_headers[i].name;
    return NULL;
}

/**
 * Vérifie si un numéro de protocole est un en-tête d'extension IPv6
 * @param nh Numéro de protocole (Next Header)
 * @return 1 si c'est un en-tête d'extension, 0 sinon
 */
static int is_extension_header(uint8_t nh) {
    return nh == 0 || nh == 43 || nh == 44 || nh == 50 || nh == 51 || nh == 60 || nh == 135;
}

/**
 * Retourne le tag descriptif d'une adresse IPv6
 * @param ip Chaîne de caractères représentant l'adresse IPv6
 */
static const char* get_ipv6_tag(const char *ip) {
    if(strcmp(ip, "::") == 0) return "UNSPECIFIED";
    if(strcmp(ip, "::1") == 0) return "LOOPBACK";
    if(strncmp(ip, "ff", 2) == 0) return "MULTICAST";
    if(strncmp(ip, "fe80:", 5) == 0) return "LINK-LOCAL";
    if(strncmp(ip, "fc", 2) == 0 || strncmp(ip, "fd", 2) == 0) return "UNIQUE-LOCAL";
    return NULL;
}

/**
 * Affiche une adresse IPv6 avec son tag descriptif
 * @param indent Indentation en espaces
 * @param label Label à afficher avant l'adresse (ex: "Source", "Destination")
 * @param ip Chaîne de caractères représentant l'adresse IPv6
 */
static void print_ip6_with_tag(int indent, const char *label, const char *ip) {
    const char *tag = get_ipv6_tag(ip);
    print_indent(indent);
    printf("      %s: %s%s%s%s\n", label, ip, tag ? " [" : "", tag ? tag : "", tag ? "]" : "");
}

// Parse et affiche un en-tête IPv6

int parse_ipv6(const u_char *packet, int length, int verbosity, int indent, uint8_t *next_hdr) {
    if(length < (int)sizeof(struct ip6_hdr)) {
        fprintf(stderr, "IPv6: Paquet trop court\n");
        return 0;
    }
    
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)packet;
    *next_hdr = ip6->ip6_nxt;
    uint32_t v_tfl = ntohl(ip6->ip6_flow);

    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(dst_ip));

    if(verbosity == 2) {
        print_indent(indent);
        printf("IPv6: %s -> %s [next=%u hop=%u]\n", src_ip, dst_ip, ip6->ip6_nxt, ip6->ip6_hlim);
    }
    else if(verbosity == 3) {
        print_indent(indent);
        printf("[L3] IPv6 Header:\n");
        print_indent(indent);
        printf("      Version: %u, TC: 0x%02x, Flow: 0x%05x\n",
               (v_tfl >> 28) & 0xF, (v_tfl >> 20) & 0xFF, v_tfl & 0xFFFFF);
        print_indent(indent);
        printf("      Payload Len: %u, Next Hdr: %u, Hop Limit: %u\n",
               ntohs(ip6->ip6_plen), ip6->ip6_nxt, ip6->ip6_hlim);
        print_ip6_with_tag(indent, "Source IP   ", src_ip);
        print_ip6_with_tag(indent, "Dest IP     ", dst_ip);
    }
    
    /* Parcourir la chaîne d'en-têtes d'extension */
    int offset = sizeof(struct ip6_hdr);
    uint8_t current = ip6->ip6_nxt;
    
    for(int count = 0; is_extension_header(current) && offset < length && count < 10; count++) {
        if(offset + 2 > length) break;
        
        const u_char *ext = packet + offset;
        uint8_t next = ext[0];
        
        /* No Next Header = fin de chaîne */
        if(current == 59) {
            *next_hdr = current;
            return offset;
        }
        
        /* Fragment Header = taille fixe 8 octets */
        int ext_size = (current == 44) ? 8 : (ext[1] + 1) * 8;
        if(offset + ext_size > length) break;
        
        if(verbosity == 3) {
            const char *name = get_ext_header_name(current);
            print_indent(indent + 2);
            printf("Extension: %s (%d bytes)\n", name ? name : "Unknown", ext_size);
        }
        
        offset += ext_size;
        current = next;
    }
    
    *next_hdr = current;
    return offset;
}

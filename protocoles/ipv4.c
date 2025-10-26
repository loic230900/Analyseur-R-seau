#include "ipv4.h"
#include <stdio.h>
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
        printf("IPv4: src=%s, dst=%s, proto=%u, ttl=%u\n", src_ip, dst_ip, ip->protocol, ip->ttl);
    }
    // verbosite 3 detaillee
    else if (verbosity == 3) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("IPv4:\n");

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Version: %u, IHL: %u (%d bytes), TOS: 0x%02x\n", ip->version, ip->ihl, ihl, ip->tos);

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Total Length: %u, Identification: 0x%04x\n", ntohs(ip->tot_len), ntohs(ip->id));

        uint16_t frag_off = ntohs(ip->frag_off);
        uint8_t flags = (frag_off >> 13) & 0x7; // Reserved, DF, MF
        uint16_t offset = frag_off & 0x1FFF;

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Flags: 0x%x, Fragment Offset: %u\n", flags, offset);

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("TTL: %u, Protocol: %u, Checksum: 0x%04x\n", ip->ttl, ip->protocol, ntohs(ip->check));

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Source IP: %s\n", src_ip);

        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Destination IP: %s\n", dst_ip);
        if (ihl > 20) {
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Options: %d bytes\n", ihl - 20);
        }
    }
    return ihl;
}
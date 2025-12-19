/**
 * Analyseur de messages DNS - VERSION REFACTORISÉE
 * 
 * Ce module implémente le parsing complet des messages DNS conformément aux RFCs.
 * Refactorisé pour réduire la duplication et améliorer la maintenabilité.
 * 
 */

#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"

#ifndef UCHAR_TYPEDEF_GUARD
#define UCHAR_TYPEDEF_GUARD
typedef unsigned char u_char;
#endif

/* Tables de correspondance pour types, classes, opcodes et rcodes DNS */

static const struct { uint16_t code; const char *name; } dns_types[] = {
    {DNS_TYPE_A, "A"}, {DNS_TYPE_NS, "NS"}, {DNS_TYPE_CNAME, "CNAME"},
    {DNS_TYPE_SOA, "SOA"}, {DNS_TYPE_PTR, "PTR"}, {DNS_TYPE_MX, "MX"},
    {DNS_TYPE_TXT, "TXT"}, {DNS_TYPE_AAAA, "AAAA"}, {DNS_TYPE_SRV, "SRV"},
    {DNS_TYPE_OPT, "OPT"}, {DNS_TYPE_DS, "DS"}, {DNS_TYPE_RRSIG, "RRSIG"},
    {DNS_TYPE_NSEC, "NSEC"}, {DNS_TYPE_DNSKEY, "DNSKEY"}, {DNS_TYPE_SVCB, "SVCB"},
    {DNS_TYPE_HTTPS, "HTTPS"}, {DNS_TYPE_AXFR, "AXFR"}, {DNS_TYPE_ANY, "ANY"},
    {DNS_TYPE_CAA, "CAA"}, {13, "HINFO"}, {35, "NAPTR"}, {0, NULL}
};

static const struct { uint16_t code; const char *name; } dns_classes[] = {
    {DNS_CLASS_IN, "IN"}, {DNS_CLASS_CH, "CH"}, {0, NULL}
};

static const struct { uint8_t code; const char *name; } dns_opcodes[] = {
    {0, "QUERY"}, {1, "IQUERY"}, {2, "STATUS"}, {4, "NOTIFY"}, {5, "UPDATE"}, {255, NULL}
};

static const struct { uint8_t code; const char *name; } dns_rcodes[] = {
    {0, "NOERROR"}, {1, "FORMERR"}, {2, "SERVFAIL"}, {3, "NXDOMAIN"},
    {4, "NOTIMP"}, {5, "REFUSED"}, {6, "YXDOMAIN"}, {7, "YXRRSET"},
    {8, "NXRRSET"}, {9, "NOTAUTH"}, {10, "NOTZONE"}, {255, NULL}
};

const char* dns_type_to_str(uint16_t type) {
    for (int i = 0; dns_types[i].name != NULL; i++)
        if (dns_types[i].code == type) return dns_types[i].name;
    return "UNKNOWN";
}

const char* dns_class_to_str(uint16_t class) {
    for (int i = 0; dns_classes[i].name != NULL; i++)
        if (dns_classes[i].code == class) return dns_classes[i].name;
    return "UNKNOWN";
}

const char* dns_opcode_to_str(uint8_t opcode) {
    for (int i = 0; dns_opcodes[i].name != NULL; i++)
        if (dns_opcodes[i].code == opcode) return dns_opcodes[i].name;
    return "UNKNOWN";
}

const char* dns_rcode_to_str(uint8_t rcode) {
    for (int i = 0; dns_rcodes[i].name != NULL; i++)
        if (dns_rcodes[i].code == rcode) return dns_rcodes[i].name;
    return "UNKNOWN";
}

const char* dns_bpf_all(void) {
    return "(udp port 53 or tcp port 53)";
}

/* Vérifications limites pour éviter les lectures hors bornes ; retourne 0 si dépassement */

#define CHECK_BOUNDS(offset, needed, limit) \
    do { if ((offset) + (needed) > (limit)) return 0; } while(0)

/* Décodage des noms DNS avec gestion de la compression (pointeurs 0xC0) */

int dns_decode_name(const u_char *packet, int length, int base_offset, int name_offset, 
                    char *out, int out_len, int *consumed) {
    int pos = name_offset;
    int out_pos = 0;
    int followed_pointer = 0;
    int pointer_count = 0;
    *consumed = 0;

    // boucle de décodage
    while (1) {
        if (pos >= length) return 0;
        uint8_t len = packet[pos];

        if (len == 0) {     // fin du nom
            if (!followed_pointer) (*consumed)++;
            if (out_pos == 0) out[out_pos++] = '.';
            out[out_pos] = '\0';
            return 1;
        }

        if ((len & 0xC0) == 0xC0) { // pointeur de compression  
            if (pos + 1 >= length) return 0;
            uint16_t ptr = ((len & 0x3F) << 8) | packet[pos + 1];
            if (base_offset + ptr >= length) return 0;
            if (!followed_pointer) {
                *consumed += 2;
                followed_pointer = 1;
            }
            if (++pointer_count > DNS_MAX_POINTERS) return 0; // coupe les boucles de compression
            pos = base_offset + ptr;
            continue;
        }

        if (len & 0xC0) return 0;               // valeurs 10/01 réservées
        if (len > DNS_MAX_LABEL_LEN) return 0;   // label > 63 interdit
        CHECK_BOUNDS(pos, 1 + len, length);     // paquet assez long ?
        CHECK_BOUNDS(out_pos, len + 2, out_len);// buffer sortie assez grand ?

        if (out_pos > 0) out[out_pos++] = '.';
        memcpy(out + out_pos, packet + pos + 1, len);
        out_pos += len;
        pos += len + 1;
        if (!followed_pointer) (*consumed) += len + 1;
    }
}

/* Affichage des RDATA selon le type d’enregistrement DNS */

/* Contexte partagé pour afficher les RDATA selon le type */
typedef struct {
    const u_char *packet;
    int length;
    int base_offset;
    int rdata_offset;
    uint16_t rdlength;
    int verbosity;
    int indent;
} rr_context_t;

static void print_rr_a(const rr_context_t *ctx) {
    // A: 4 octets d'adresse IPv4
    if (ctx->rdlength == 4) {
        const u_char *a = ctx->packet + ctx->rdata_offset;
        printf("A -> %u.%u.%u.%u\n", a[0], a[1], a[2], a[3]);
    } else {
        printf("A (len=%u invalid)\n", ctx->rdlength);
    }
}

static void print_rr_aaaa(const rr_context_t *ctx) {
    // AAAA: 16 octets d'adresse IPv6
    if (ctx->rdlength == 16) {
        struct in6_addr addr6;
        char ip6[INET6_ADDRSTRLEN];
        memcpy(&addr6, ctx->packet + ctx->rdata_offset, 16);
        if (inet_ntop(AF_INET6, &addr6, ip6, sizeof(ip6)) != NULL) {
            printf("AAAA -> %s\n", ip6);
        } else {
            printf("AAAA -> (invalid)\n");
        }
    } else {
        printf("AAAA (len=%u invalid)\n", ctx->rdlength);
    }
}

static void print_rr_name(const rr_context_t *ctx, const char *label) {
    // NS/CNAME/PTR: nom compressé
    char target[DNS_MAX_NAME_LEN];
    int consumed;
    if (dns_decode_name(ctx->packet, ctx->length, ctx->base_offset, 
                        ctx->rdata_offset, target, sizeof(target), &consumed)) {
        printf("%s -> %s\n", label, target);
    } else {
        printf("%s -> (invalid)\n", label);
    }
}

static void print_rr_mx(const rr_context_t *ctx) {
    // MX: préférence (2 octets) + nom
    if (ctx->rdlength >= 2) {
        uint16_t pref = ntohs(*(uint16_t*)(ctx->packet + ctx->rdata_offset));
        char exch[DNS_MAX_NAME_LEN];
        int consumed;
        if (dns_decode_name(ctx->packet, ctx->length, ctx->base_offset,
                            ctx->rdata_offset + 2, exch, sizeof(exch), &consumed)) {
            printf("MX -> Pref=%u %s\n", pref, exch);
        } else {
            printf("MX -> Pref=%u (invalid)\n", pref);
        }
    } else {
        printf("MX (len=%u invalid)\n", ctx->rdlength);
    }
}

static void print_rr_txt(const rr_context_t *ctx) {
    // TXT: segments longueur + texte
    printf("TXT -> \"");
    int pos = ctx->rdata_offset;
    int end = ctx->rdata_offset + ctx->rdlength;
    while (pos < end) {
        uint8_t seglen = ctx->packet[pos++];
        if (pos + seglen > end) break;
        for (int i = 0; i < seglen; i++) {
            uint8_t c = ctx->packet[pos + i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        pos += seglen;
        if (pos < end) printf(" ");
    }
    printf("\"\n");
}

static void print_rr_soa(const rr_context_t *ctx) {
    // SOA: deux noms + 5 champs 32 bits
    char mname[DNS_MAX_NAME_LEN], rname[DNS_MAX_NAME_LEN];
    int c1, c2, p = ctx->rdata_offset;
    
    if (dns_decode_name(ctx->packet, ctx->length, ctx->base_offset, p, mname, sizeof(mname), &c1)) {
        p += c1;
        if (dns_decode_name(ctx->packet, ctx->length, ctx->base_offset, p, rname, sizeof(rname), &c2)) {
            p += c2;
            if (p + 20 <= ctx->rdata_offset + ctx->rdlength) {
                uint32_t serial  = ntohl(*(uint32_t*)(ctx->packet + p)); p += 4;
                uint32_t refresh = ntohl(*(uint32_t*)(ctx->packet + p)); p += 4;
                uint32_t retry   = ntohl(*(uint32_t*)(ctx->packet + p)); p += 4;
                uint32_t expire  = ntohl(*(uint32_t*)(ctx->packet + p)); p += 4;
                uint32_t minimum = ntohl(*(uint32_t*)(ctx->packet + p));
                printf("SOA -> M=%s R=%s s=%u ref=%u ret=%u exp=%u min=%u\n",
                       mname, rname, serial, refresh, retry, expire, minimum);
                return;
            }
        }
    }
    printf("SOA -> invalid\n");
}

static void print_rr_opt(const rr_context_t *ctx, uint16_t class, uint32_t ttl) {
    // OPT (EDNS0): classe=taille UDP, TTL porte flags étendus
    uint8_t edns_version = (uint8_t)((ttl >> 16) & 0xFF);  // shift de 16 bits pour obtenir le byte de version
    uint16_t flags = (uint16_t)(ttl & 0xFFFF);  
    int do_bit = (flags >> 15) & 0x01;  // DO bit est le bit 15
    printf("OPT -> EDNS0 UDPsize=%u ver=%u DO=%d", class, edns_version, do_bit);
    
    // options si présentes
    if (ctx->rdlength > 0) {
        printf(" opts=");
        int pos = ctx->rdata_offset, end = ctx->rdata_offset + ctx->rdlength, first = 1;
        while (pos + 4 <= end) {
            uint16_t opt_code = ntohs(*(uint16_t*)(ctx->packet + pos)); pos += 2;
            uint16_t opt_len = ntohs(*(uint16_t*)(ctx->packet + pos)); pos += 2;
            if (pos + opt_len > end) break;
            if (!first) printf(",");
            first = 0;
            switch(opt_code) {
                case 3: printf("NSID"); break;
                case 8: printf("ECS"); break;
                case 10: printf("Cookie"); break;
                case 15: printf("ExtErr"); break;
                default: printf("code%u", opt_code); break;
            }
            pos += opt_len;
        }
    }
    printf("\n");
}

static void print_rr_srv(const rr_context_t *ctx) {
    // SRV: priorité, poids, port, cible
    if (ctx->rdlength >= 6) {
        uint16_t priority = ntohs(*(uint16_t*)(ctx->packet + ctx->rdata_offset));
        uint16_t weight = ntohs(*(uint16_t*)(ctx->packet + ctx->rdata_offset + 2));
        uint16_t port = ntohs(*(uint16_t*)(ctx->packet + ctx->rdata_offset + 4));
        char target[DNS_MAX_NAME_LEN];
        int consumed;
        if (dns_decode_name(ctx->packet, ctx->length, ctx->base_offset,
                            ctx->rdata_offset + 6, target, sizeof(target), &consumed)) {
            printf("SRV -> Pri=%u Wt=%u Port=%u Target=%s\n", priority, weight, port, target);
        } else {
            printf("SRV -> Pri=%u Wt=%u Port=%u (invalid)\n", priority, weight, port);
        }
    } else {
        printf("SRV (len=%u invalid)\n", ctx->rdlength);
    }
}

static void print_rr_caa(const rr_context_t *ctx) {
    // CAA: flags + tag + valeur ASCII limitée
    if (ctx->rdlength >= 2) {
        uint8_t flags_caa = ctx->packet[ctx->rdata_offset];
        uint8_t tag_len = ctx->packet[ctx->rdata_offset + 1];
        if (ctx->rdata_offset + 2 + tag_len <= ctx->rdata_offset + ctx->rdlength) {
            char tag[64] = "";
            int tl = tag_len < 63 ? tag_len : 63;
            memcpy(tag, ctx->packet + ctx->rdata_offset + 2, (size_t)tl);
            tag[tl] = '\0';
            printf("CAA -> Flags=%u Tag=%s Value=", flags_caa, tag);
            int value_offset = ctx->rdata_offset + 2 + tag_len;
            int value_len = ctx->rdlength - 2 - tag_len;
            for (int i = 0; i < value_len && i < 32; i++) {
                uint8_t c = ctx->packet[value_offset + i];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            if (value_len > 32) printf("...");
            printf("\n");
            return;
        }
    }
    printf("CAA (invalid)\n");
}

static void print_rr_generic(const rr_context_t *ctx, uint16_t type) {
    // Fallback pour types non détaillés
    int is_printable = (ctx->rdlength > 0);
    for (int i = 0; i < ctx->rdlength && is_printable; i++) {
        uint8_t c = ctx->packet[ctx->rdata_offset + i];
        if ((c < 32 || c > 126) && c != 9 && c != 10 && c != 13) is_printable = 0;
    }
    
    if (is_printable && ctx->rdlength > 0) {
        printf("DATA -> ");
        for (int i = 0; i < ctx->rdlength; i++) {
            uint8_t c = ctx->packet[ctx->rdata_offset + i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    } else {
        printf("TYPE=%u RDLEN=%u", type, ctx->rdlength);
        if (ctx->rdlength > 0) printf(" HEX=");
        for (int i = 0; i < ctx->rdlength && i < 12; i++) {
            printf("%02x", ctx->packet[ctx->rdata_offset + i]);
            if (i < ctx->rdlength - 1 && i < 11) printf(" ");
        }
        if (ctx->rdlength > 12) printf(" ...");
        printf("\n");
    }
}

/* Parsing commun des questions et Resource Records */

/* Parse une question DNS et renvoie les octets consommés */
static int parse_dns_question(const u_char *packet, int length, int base_offset, int offset, 
                              int verbosity, int indent, char *qname_out, int qname_len,
                              int *bytes_consumed, uint16_t *out_qtype, uint16_t *out_qclass) {
    int start = offset, name_consumed;
    char qname[DNS_MAX_NAME_LEN];

    if (!dns_decode_name(packet, length, base_offset, offset, qname, sizeof(qname), &name_consumed))
        return 0;
    offset += name_consumed;

    CHECK_BOUNDS(offset, 4, length);
    uint16_t qtype  = ntohs(*(uint16_t*)(packet + offset)); offset += 2;
    uint16_t qclass = ntohs(*(uint16_t*)(packet + offset)); offset += 2;

    if (out_qtype) *out_qtype = qtype;
    if (out_qclass) *out_qclass = qclass;

    if (verbosity >= 3) {
        printf("%*sQuestion: %s %s %s\n", indent, "",
               qname, dns_class_to_str(qclass), dns_type_to_str(qtype));
    }

    if (qname_out && qname_len > 0) {
        strncpy(qname_out, qname, (size_t)(qname_len - 1));
        qname_out[qname_len - 1] = '\0';
    }

    *bytes_consumed = offset - start;
    return 1;
}

/* Parse un Resource Record générique et délègue l'affichage selon le type */
static int parse_dns_rr(const u_char *packet, int length, int base_offset, int offset,
                        int verbosity, int indent, const char *section_label, int *bytes_consumed) {
    int start = offset, name_consumed;
    char name[DNS_MAX_NAME_LEN];

    if (!dns_decode_name(packet, length, base_offset, offset, name, sizeof(name), &name_consumed))
        return 0;
    offset += name_consumed;

    CHECK_BOUNDS(offset, 10, length);
    uint16_t type     = ntohs(*(uint16_t*)(packet + offset)); offset += 2;
    uint16_t class    = ntohs(*(uint16_t*)(packet + offset)); offset += 2;
    uint32_t ttl      = ntohl(*(uint32_t*)(packet + offset)); offset += 4;
    uint16_t rdlength = ntohs(*(uint16_t*)(packet + offset)); offset += 2;

    CHECK_BOUNDS(offset, rdlength, length);

    if (verbosity >= 3) {
        printf("%*s%s: %s %s %s TTL=%u ", indent, "", section_label,
               name, dns_class_to_str(class), dns_type_to_str(type), ttl);

        rr_context_t ctx = {packet, length, base_offset, offset, rdlength, verbosity, indent};
        
        switch (type) {
            case DNS_TYPE_A:      print_rr_a(&ctx); break;
            case DNS_TYPE_AAAA:   print_rr_aaaa(&ctx); break;
            case DNS_TYPE_NS:     print_rr_name(&ctx, "NS"); break;
            case DNS_TYPE_CNAME:  print_rr_name(&ctx, "CNAME"); break;
            case DNS_TYPE_PTR:    print_rr_name(&ctx, "PTR"); break;
            case DNS_TYPE_MX:     print_rr_mx(&ctx); break;
            case DNS_TYPE_TXT:    print_rr_txt(&ctx); break;
            case DNS_TYPE_SOA:    print_rr_soa(&ctx); break;
            case DNS_TYPE_OPT:    print_rr_opt(&ctx, class, ttl); break; // EDNS0 pseudo-RR
            case 33:              print_rr_srv(&ctx); break;
            case 257:             print_rr_caa(&ctx); break;
            default:              print_rr_generic(&ctx, type); break;   // fallback pour types non détaillés
        }
    }

    *bytes_consumed = offset + rdlength - start;
    return 1;
}

/* Extraction synthétique d’une valeur d’answer pour le résumé v1 */

/* Extrait la première réponse qui correspond au qtype (pour le résumé v1) */
static int extract_answer_value(const u_char *packet, int caplen, int base_offset, 
                                int ans_offset, uint16_t target_type, char *out, int out_len) {
    char ans_name[DNS_MAX_NAME_LEN];
    int ans_consumed;
    
    if (!dns_decode_name(packet, caplen, base_offset, ans_offset, ans_name, sizeof(ans_name), &ans_consumed))
        return 0;
    
    int ans_type_offset = ans_offset + ans_consumed;
    CHECK_BOUNDS(ans_type_offset, 10, caplen);
    
    uint16_t ans_type = (packet[ans_type_offset] << 8) | packet[ans_type_offset + 1];
    uint16_t ans_rdlen = (packet[ans_type_offset + 8] << 8) | packet[ans_type_offset + 9]; // longueur RDATA
    int rdata_offset = ans_type_offset + 10;
    
    if (ans_type != target_type) return 0;
    CHECK_BOUNDS(rdata_offset, ans_rdlen, caplen);
    
    if (ans_type == DNS_TYPE_A && ans_rdlen == 4) {
        snprintf(out, (size_t)out_len, " -> %u.%u.%u.%u",
                packet[rdata_offset], packet[rdata_offset + 1],
                packet[rdata_offset + 2], packet[rdata_offset + 3]);
        return 1;
    } else if (ans_type == DNS_TYPE_AAAA && ans_rdlen == 16) {
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, (const void*)&packet[rdata_offset], ipv6, sizeof(ipv6));
        snprintf(out, (size_t)out_len, " -> %s", ipv6);
        return 1;
    } else if ((ans_type == DNS_TYPE_CNAME || ans_type == DNS_TYPE_NS) && ans_rdlen > 0) {
        char target[DNS_MAX_NAME_LEN];
        int consumed;
        if (dns_decode_name(packet, caplen, base_offset, rdata_offset, target, sizeof(target), &consumed)) {
            snprintf(out, (size_t)out_len, " -> %.250s", target); // limite pour rester dans le buffer résumé
            return 1;
        }
    } else if (ans_type == DNS_TYPE_MX && ans_rdlen > 2) {
        char mx[DNS_MAX_NAME_LEN];
        int consumed;
        if (dns_decode_name(packet, caplen, base_offset, rdata_offset + 2, mx, sizeof(mx), &consumed)) { // skip preference
            snprintf(out, (size_t)out_len, " -> %.250s", mx); // idem limitation
            return 1;
        }
    }
    
    return 1;  /* Type matched but no detailed value */
}

/* Fonctions principales de parsing DNS (verbosités 1, 2 et 3) */

/* Parse complet d'un message DNS (UDP ou TCP) pour les verbosités 2 et 3 */
int parse_dns(const u_char *packet, int length, int verbosity, int indent, 
              int is_tcp, int *is_response, char *first_qname, int qname_len) {
    const u_char *msg = packet;
    int msg_len = length, total_consumed = 0;

    if (is_tcp) {
        CHECK_BOUNDS(0, 2, msg_len);
        uint16_t mlen = (packet[0] << 8) | packet[1]; // longueur DNS encapsulée dans TCP
        if (2 + (int)mlen > msg_len) return 0;
        msg = packet + 2;
        msg_len = (int)mlen;
        total_consumed = 2;
    }

    int offset = 0;
    CHECK_BOUNDS(offset, 12, msg_len);

    /* Parse header */
    uint16_t id      = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t flags   = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t qdcount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t ancount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t nscount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t arcount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;

    uint8_t qr     = (flags >> 15) & 0x01;
    uint8_t opcode = (flags >> 11) & 0x0F;
    uint8_t aa     = (flags >> 10) & 0x01;
    uint8_t tc     = (flags >> 9)  & 0x01;
    uint8_t rd     = (flags >> 8)  & 0x01;
    uint8_t ra     = (flags >> 7)  & 0x01;
    uint8_t rcode  = flags & 0x0F;

    if (is_response) *is_response = qr;

    if (verbosity == 3) {
        print_indent(indent);
        printf("[L7] DNS Header:\n");
        print_indent(indent);
        printf("    Transaction ID: 0x%04x\n", id);
        print_indent(indent);
        printf("    Flags: QR=%u (%s), Opcode=%u (%s), AA=%u, TC=%u, RD=%u, RA=%u\n",
               qr, qr ? "Response" : "Request", opcode, dns_opcode_to_str(opcode), aa, tc, rd, ra);
        print_indent(indent);
        printf("    Response code: %u (%s)\n", rcode, dns_rcode_to_str(rcode));
        print_indent(indent);
        printf("    Questions: %u, Answers: %u, Authority: %u, Additional: %u\n",
               qdcount, ancount, nscount, arcount);
    }

    /* Parse sections (Questions puis RRs) */
    for (int i = 0; i < (int)qdcount; i++) {
        int consumed;
        uint16_t qtype, qclass;
        if (!parse_dns_question(msg, msg_len, 0, offset, verbosity, indent + 4,
                                (i == 0 ? first_qname : NULL), qname_len, &consumed, &qtype, &qclass))
            return 0;
        offset += consumed; // avance de la longueur exacte décodée
    }

    for (int i = 0; i < (int)ancount; i++) {
        if (i == 0 && verbosity >= 3) { print_indent(indent); printf("    -- Answers --\n"); }
        int consumed;
        if (!parse_dns_rr(msg, msg_len, 0, offset, verbosity, indent + 4, "Answer", &consumed)) return 0;
        offset += consumed; // avance après chaque RR Answer
    }

    for (int i = 0; i < (int)nscount; i++) {
        if (i == 0 && verbosity >= 3) { print_indent(indent); printf("    -- Authority --\n"); }
        int consumed;
        if (!parse_dns_rr(msg, msg_len, 0, offset, verbosity, indent + 4, "Authority", &consumed)) return 0;
        offset += consumed; // avance après chaque RR Authority
    }

    for (int i = 0; i < (int)arcount; i++) {
        if (i == 0 && verbosity >= 3) { print_indent(indent); printf("    -- Additional --\n"); }
        int consumed;
        if (!parse_dns_rr(msg, msg_len, 0, offset, verbosity, indent + 4, "Additional", &consumed)) return 0;
        offset += consumed; // avance après chaque RR Additional
    }

    /* Verbosity 2: sortie synthétique sur une ligne */
    if (verbosity == 2 && first_qname && qdcount > 0) {
        print_indent(indent);
        printf("DNS: %s %s [AN=%u]\n", qr ? "Response" : "Query", first_qname, ancount);
    }

    return total_consumed + offset;
}

/* Résumé concis (verbosité 1) : premier qname + éventuelle première réponse */
int dns_v1_summary(const u_char *packet, int caplen, int offset_dns_payload, char *resume, int is_tcp) {
    if (is_tcp) {
        CHECK_BOUNDS(offset_dns_payload, 2, caplen);
        offset_dns_payload += 2;
    }
    
    CHECK_BOUNDS(offset_dns_payload, 12, caplen);
    const u_char *dns = packet + offset_dns_payload;
    uint16_t flags = (dns[2] << 8) | dns[3];
    int qr = (flags >> 15) & 0x1;
    uint16_t ancount = (dns[6] << 8) | dns[7];
    
    char qname[DNS_MAX_NAME_LEN];
    int consumed;
    if (!dns_decode_name(packet, caplen, offset_dns_payload, offset_dns_payload + 12,
                         qname, sizeof(qname), &consumed))
        return 0;
    
    if (qname[0] == 0 || qname[0] == '.') strncpy(qname, "(root)", sizeof(qname) - 1);
    
    int qtype_offset = offset_dns_payload + 12 + consumed;
    CHECK_BOUNDS(qtype_offset, 4, caplen);
    uint16_t qtype = (dns[12 + consumed] << 8) | dns[12 + consumed + 1];
    const char* type_str = dns_type_to_str(qtype);
    
    if (qr && ancount > 0) { // réponse : tenter d'afficher une première valeur
        int ans_offset = qtype_offset + 4;
        char answer_data[256] = "";
        
        /* Recherche d'un RR qui matche le qtype (limité à quelques essais) */
        for (int i = 0; i < ancount && i < 5 && !answer_data[0]; i++) {
            if (extract_answer_value(packet, caplen, offset_dns_payload, ans_offset, qtype, answer_data, sizeof(answer_data))) {
                safe_strcat(resume, " Resp: ", RESUME_BUFFER_SIZE);
                safe_strcat(resume, qname, RESUME_BUFFER_SIZE);
                safe_strcat(resume, " (", RESUME_BUFFER_SIZE);
                safe_strcat(resume, type_str, RESUME_BUFFER_SIZE);
                safe_strcat(resume, ")", RESUME_BUFFER_SIZE);
                safe_strcat(resume, answer_data, RESUME_BUFFER_SIZE);
                return 1;
            }
            // Heuristique de saut vers le RR suivant (approximation pour résumé v1)
            ans_offset += 12 + 16;
        }
        
        safe_strcat(resume, " Resp: ", RESUME_BUFFER_SIZE);
        safe_strcat(resume, qname, RESUME_BUFFER_SIZE);
        safe_strcat(resume, " (", RESUME_BUFFER_SIZE);
        safe_strcat(resume, type_str, RESUME_BUFFER_SIZE);
        safe_strcat(resume, ") -> No record", RESUME_BUFFER_SIZE);
    } else {
        safe_strcat(resume, qr ? " Resp: " : " Query: ", RESUME_BUFFER_SIZE);
        safe_strcat(resume, qname, RESUME_BUFFER_SIZE);
        safe_strcat(resume, " (", RESUME_BUFFER_SIZE);
        safe_strcat(resume, type_str, RESUME_BUFFER_SIZE);
        safe_strcat(resume, ")", RESUME_BUFFER_SIZE);
    }
    
    return 1;
}

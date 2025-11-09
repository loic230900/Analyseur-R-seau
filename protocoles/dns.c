#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h> /* pour u_char */
#include <arpa/inet.h> /* inet_ntop pour affichage IP lisible */

/* Fallback au cas où u_char n'est pas défini par les en-têtes inclus */
#ifndef __UCHAR_TYPE_DEFINED__
#ifndef u_char
typedef unsigned char u_char;
#endif
#endif



// Fonctions utilitaires pour obtenir des représentations textuelles
const char* dns_type_to_str(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_OPT: return "OPT";
        default: return "UNKNOWN";
    }
}

const char* dns_class_to_str(uint16_t klass) {
    switch (klass) {
        case DNS_CLASS_IN: return "IN";
        case DNS_CLASS_CH: return "CH";
        default: return "UNKNOWN";
    }
}

const char* dns_opcode_to_str(uint8_t opcode) {
    switch (opcode) {
        case 0: return "QUERY";
        case 1: return "IQUERY";
        case 2: return "STATUS";
        default: return "UNKNOWN";
    }
}

const char* dns_rcode_to_str(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

/* Expression BPF pour tout le trafic DNS (UDP et TCP port 53) */
const char* dns_bpf_all(void) {
    return "(udp port 53 or tcp port 53)";
}


// Décode un nom DNS à partir d'un offset.
int dns_decode_name(const u_char *packet, int length, int base_offset,
                    int name_offset, char *out, int out_len, int *consumed) {
    int pos = name_offset;
    int out_pos = 0;
    int followed_pointer = 0;
    int pointer_count = 0;
    *consumed = 0;

    while (1) {
        if (pos >= length) return 0;
        uint8_t len = packet[pos];

        /* Fin de nom */
        if (len == 0) {
            if (!followed_pointer) (*consumed)++;
            if (out_pos == 0) {
                out[out_pos++] = '.';
            }
            out[out_pos] = '\0';
            return 1;
        }

        /* Pointeur de compression */
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= length) return 0;
            uint16_t ptr = ((len & 0x3F) << 8) | packet[pos + 1]; // pointeur 16 bits 
            if (base_offset + ptr >= length) return 0;
            if (!followed_pointer) {
                *consumed += 2;
                followed_pointer = 1;
            }
            if (++pointer_count > DNS_MAX_POINTERS) return 0;
            pos = base_offset + ptr;
            continue;
        }

        /* Format invalide */
        if (len & 0xC0) return 0;
        if (len > DNS_MAX_LABEL_LEN) return 0;
        if (pos + 1 + len > length) return 0;
        if (out_pos + len + 2 > out_len) return 0;

        if (out_pos > 0) out[out_pos++] = '.';
        memcpy(out + out_pos, packet + pos + 1, len);
        out_pos += len;

        pos += len + 1;
        if (!followed_pointer) (*consumed) += len + 1; 
    }
}

// Analyse et affiche une question DNS selon la verbosité
static int parse_dns_question(const u_char *packet, int length, int base_offset, int offset, int verbosity, int indent,
                              char *qname_out, int qname_len,
                              int *bytes_consumed,
                              uint16_t *out_qtype, uint16_t *out_qclass) {
    int start = offset;
    int name_consumed;
    char qname[DNS_MAX_NAME_LEN];

    if (!dns_decode_name(packet, length, base_offset, offset,
                         qname, sizeof(qname), &name_consumed)) {
        return 0;
    }
    offset += name_consumed;

    if (offset + 4 > length) return 0;
    uint16_t qtype  = ntohs(*(uint16_t*)(packet + offset)); offset += 2;
    uint16_t qclass = ntohs(*(uint16_t*)(packet + offset)); offset += 2;

    if (out_qtype) *out_qtype = qtype;
    if (out_qclass) *out_qclass = qclass;

    if (verbosity >= 3) {
        printf("%*sQuestion: %s %s %s\n",
               indent, "",
               qname,
               dns_class_to_str(qclass),
               dns_type_to_str(qtype));
    }

    if (qname_out) {
        strncpy(qname_out, qname, qname_len - 1);
        qname_out[qname_len - 1] = '\0';
    }

    *bytes_consumed = offset - start;
    return 1;
}

// Analyse et affiche une ressource DNS selon la verbosité
static int parse_dns_rr(const u_char *packet, int length,
                        int base_offset, int offset,
                        int verbosity, int indent,
                        const char *section_label,
                        int *bytes_consumed) {
    int start = offset;
    int name_consumed;
    char name[DNS_MAX_NAME_LEN];

    if (!dns_decode_name(packet, length, base_offset, offset,
                         name, sizeof(name), &name_consumed)) {
        return 0;
    }
    offset += name_consumed;

    if (offset + 10 > length) return 0;
    uint16_t type     = ntohs(*(uint16_t*)(packet + offset)); offset += 2;
    uint16_t klass    = ntohs(*(uint16_t*)(packet + offset)); offset += 2;
    uint32_t ttl      = ntohl(*(uint32_t*)(packet + offset)); offset += 4;
    uint16_t rdlength = ntohs(*(uint16_t*)(packet + offset)); offset += 2;

    if (offset + rdlength > length) return 0;
    int rdata_offset = offset;

    if (verbosity >= 3) {
        printf("%*s%s: %s %s %s TTL=%u ",
               indent, "",
               section_label,
               name,
               dns_class_to_str(klass),
               dns_type_to_str(type),
               ttl);
    }

    /* Décodage basique des RDATA */
    if (verbosity >= 3) {
        switch (type) {
            case DNS_TYPE_A:
                if (rdlength == 4) {
                    const u_char *a = packet + rdata_offset;
                    printf("A -> %u.%u.%u.%u\n", a[0], a[1], a[2], a[3]);
                } else {
                    printf("A (len=%u invalide)\n", rdlength);
                }
                break;

            case DNS_TYPE_AAAA:
                if (rdlength == 16) {
                    struct in6_addr addr6;
                    char ip6[INET6_ADDRSTRLEN];
                    memcpy(&addr6, packet + rdata_offset, 16);
                    if (inet_ntop(AF_INET6, &addr6, ip6, sizeof(ip6)) != NULL) {
                        printf("AAAA -> %s\n", ip6);
                    } else {
                        printf("AAAA -> (adresse invalide)\n");
                    }
                } else {
                    printf("AAAA (len=%u invalide)\n", rdlength);
                }
                break;

            case DNS_TYPE_NS:
            case DNS_TYPE_CNAME:
            case DNS_TYPE_PTR: {
                char target[DNS_MAX_NAME_LEN];
                int target_consumed;
                if (dns_decode_name(packet, length, base_offset,
                                    rdata_offset, target, sizeof(target),
                                    &target_consumed)) {
                    printf("%s -> %s\n",
                           (type == DNS_TYPE_NS ? "NS" :
                            type == DNS_TYPE_CNAME ? "CNAME" : "PTR"),
                           target);
                } else {
                    printf("Nom invalide\n");
                }
                break;
            }

            case DNS_TYPE_MX:
                if (rdlength >= 2) {
                    uint16_t pref = ntohs(*(uint16_t*)(packet + rdata_offset));
                    char exch[DNS_MAX_NAME_LEN];
                    int exch_consumed;
                    if (dns_decode_name(packet, length, base_offset,
                                        rdata_offset + 2, exch, sizeof(exch),
                                        &exch_consumed)) {
                        printf("MX -> Pref=%u %s\n", pref, exch);
                    } else {
                        printf("MX -> Pref=%u (nom invalide)\n", pref);
                    }
                } else {
                    printf("MX (len=%u invalide)\n", rdlength);
                }
                break;

            case DNS_TYPE_TXT: {
                printf("TXT -> \"");
                int pos = rdata_offset;
                int end = rdata_offset + rdlength;
                while (pos < end) {
                    uint8_t seglen = packet[pos++];
                    if (pos + seglen > end) break;
                    for (int i = 0; i < seglen; i++) {
                        uint8_t c = packet[pos + i];
                        /* Affichage brut, on pourrait filtrer */
                        printf("%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                    pos += seglen;
                    if (pos < end) printf(" ");
                }
                printf("\"\n");
                break;
            }

            case DNS_TYPE_SOA: {
                /* MNAME + RNAME + 5x uint32 */
                char mname[DNS_MAX_NAME_LEN], rname[DNS_MAX_NAME_LEN];
                int c1, c2;
                int p = rdata_offset;
                if (dns_decode_name(packet, length, base_offset, p,
                                    mname, sizeof(mname), &c1)) {
                    p += c1;
                    if (dns_decode_name(packet, length, base_offset, p,
                                        rname, sizeof(rname), &c2)) {
                        p += c2;
                        if (p + 20 <= rdata_offset + rdlength) {
                            uint32_t serial  = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t refresh = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t retry   = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t expire  = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            uint32_t minimum = ntohl(*(uint32_t*)(packet + p)); p += 4;
                            printf("SOA -> M=%s R=%s serial=%u refresh=%u retry=%u expire=%u min=%u\n",
                                   mname, rname, serial, refresh, retry, expire, minimum);
                        } else {
                            printf("SOA -> structure tronquée\n");
                        }
                    } else {
                        printf("SOA -> RNAME invalide\n");
                    }
                } else {
                    printf("SOA -> MNAME invalide\n");
                }
                break;
            }

            case DNS_TYPE_OPT:
                /* EDNS0 pseudo-RR: classe = UDP payload size, TTL = extended fields */
                printf("OPT -> EDNS0 len=%u\n", rdlength);
                break;

            default:
                printf("TYPE=%u RDLEN=%u HEX=", type, rdlength);
                for (int i = 0; i < rdlength && i < 16; i++) {
                    printf("%02x", packet[rdata_offset + i]);
                    if (i < rdlength - 1 && i < 15) printf(" ");
                }
                if (rdlength > 16) printf(" ...");
                printf("\n");
                break;
        }
    }

    offset += rdlength;
    *bytes_consumed = offset - start;
    return 1;
}


// Analyse et affiche un message DNS
int parse_dns(const u_char *packet, int length, int verbosity, int indent,
              int is_tcp, int *is_response, char *first_qname, int qname_len) {
    /* Pointer/offset model: work on 'msg' starting at DNS start.
       For TCP, skip 2-byte length prefix and limit to that length. */
    const u_char *msg = packet;
    int msg_len = length;
    int total_consumed = 0;

    /* Préfixe TCP (2 octets length) */
    if (is_tcp) {
        if (msg_len < 2) return 0;
        uint16_t mlen = (packet[0] << 8) | packet[1];
        if (2 + (int)mlen > msg_len) return 0;
        msg = packet + 2;
        msg_len = (int)mlen;
        total_consumed = 2;
    }

    int offset = 0;
    int base_offset = 0; /* compression base relative to 'msg' */

    /* Header minimum */
    if (offset + 12 > msg_len) return 0;

    uint16_t id      = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t flags   = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t qdcount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t ancount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t nscount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;
    uint16_t arcount = (uint16_t)((msg[offset] << 8) | msg[offset+1]); offset += 2;

    /* convert counts/flags to host order */
    /* flags already read as network order -> host order int */
    /* qdcount... already read as host order via shifts */

    uint8_t qr     = (flags >> 15) & 0x01;
    uint8_t opcode = (flags >> 11) & 0x0F;
    uint8_t aa     = (flags >> 10) & 0x01;
    uint8_t tc     = (flags >> 9)  & 0x01;
    uint8_t rd     = (flags >> 8)  & 0x01;
    uint8_t ra     = (flags >> 7)  & 0x01;
    uint8_t rcode  = flags & 0x0F;

    if (is_response) *is_response = qr;

    if (verbosity >= 3) {
     printf("%*s[DNS] ID=0x%04x %s OPCODE=%s AA=%u TC=%u RD=%u RA=%u RCODE=%s\n",
         indent, "",
         id,
         qr ? "Response" : "Query",
         dns_opcode_to_str(opcode),
         aa, tc, rd, ra,
         dns_rcode_to_str(rcode));
     printf("%*sCounts: QD=%u AN=%u NS=%u AR=%u\n",
         indent, "", qdcount, ancount, nscount, arcount);
    }

    int printed_v2_summary = 0;

    /* Questions */
    for (int i = 0; i < (int)qdcount; i++) {
        int consumed;
        uint16_t qtype_tmp = 0, qclass_tmp = 0;
        if (!parse_dns_question(msg, msg_len,
                                 base_offset, offset,
                                 verbosity, indent + 2,
                                 (i == 0 ? first_qname : NULL), qname_len,
                                 &consumed, &qtype_tmp, &qclass_tmp)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;

        if (verbosity == 2 && i == 0 && !printed_v2_summary) {
            const char *qname = (first_qname && first_qname[0]) ? first_qname : "";
            if (qname[0]) {
                printf("%*s[DNS] id=0x%04x %s QD=%u AN=%u NS=%u AR=%u q=%s %s\n",
                       indent, "",
                       id, (qr ? "Response" : "Query"),
                       qdcount, ancount, nscount, arcount,
                       qname, dns_type_to_str(qtype_tmp));
            } else {
                printf("%*s[DNS] id=0x%04x %s QD=%u AN=%u NS=%u AR=%u\n",
                       indent, "",
                       id, (qr ? "Response" : "Query"),
                       qdcount, ancount, nscount, arcount);
            }
            printed_v2_summary = 1;
        }
    }

    /* Answers */
    if (verbosity >= 3 && ancount > 0)
        printf("%*s-- Answers --\n", indent, "");
    for (int i = 0; i < (int)ancount; i++) {
        int consumed;
        if (!parse_dns_rr(msg, msg_len,
                          base_offset, offset,
                          verbosity, indent + 2,
                          "Answer", &consumed)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;
    }

    /* Authority */
    if (verbosity >= 3 && nscount > 0)
        printf("%*s-- Authority --\n", indent, "");
    for (int i = 0; i < (int)nscount; i++) {
        int consumed;
        if (!parse_dns_rr(msg, msg_len,
                          base_offset, offset,
                          verbosity, indent + 2,
                          "Authority", &consumed)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;
    }

    /* Additional */
    if (verbosity >= 3 && arcount > 0)
        printf("%*s-- Additional --\n", indent, "");
    for (int i = 0; i < (int)arcount; i++) {
        int consumed;
        if (!parse_dns_rr(msg, msg_len,
                          base_offset, offset,
                          verbosity, indent + 2,
                          "Additional", &consumed)) {
            return 0;
        }
        offset += consumed;
        if (offset > msg_len) return 0;
    }

    if (verbosity == 2 && !printed_v2_summary) {
        /* Cas sans question ou si non imprimé pour une raison quelconque */
        printf("%*s[DNS] id=0x%04x %s QD=%u AN=%u NS=%u AR=%u\n",
               indent, "",
               id, (qr ? "Response" : "Query"),
               qdcount, ancount, nscount, arcount);
    }

    /* total consumed includes TCP prefix if present */
    return total_consumed + offset;
}
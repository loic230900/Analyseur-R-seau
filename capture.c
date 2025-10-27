#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "capture.h"
#include "protocoles/ethernet.h"
#include "protocoles/ipv4.h"
#include "protocoles/ipv6.h"
#include "protocoles/udp.h"
#include "protocoles/dhcp.h"
#include "protocoles/arp.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    capture_args_t *capture = (capture_args_t *)args;
    int verbosity = capture->verbosity;
    static int packet_count = 0;
    packet_count++;

    //Niveau 1: affichage très concis
    if (verbosity == 1) {
        const struct ether_header *eth_header = (struct ether_header *)packet;
        uint16_t ethertype = ntohs(eth_header->ether_type);
        int offset = 14; // Taille de l'en-tête Ethernet sans data
        char resume[256] = ""; //chaine pour construire le résumé

        //analyse ethernet

        //IPV4
        if(ethertype == ETHERTYPE_IP){
            strcat(resume, "IPv4");
            const struct iphdr *ip = (const struct iphdr *)(packet + offset); //en-tête IP
            int ihl = ip->ihl * 4;
            offset += ihl;

            //analyse protocole transport
            //UDP
            if(ip->protocol == IPPROTO_UDP){
                strcat(resume, " | UDP");
                const struct udphdr *udp = (const struct udphdr *)(packet + offset);
                uint16_t src_port = ntohs(udp->source);
                uint16_t dst_port = ntohs(udp->dest);
                if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68){
                    strcat(resume, " | BOOTP/DHCP");
                }
            }
        }
        //IPV6 
        else if (ethertype == ETHERTYPE_IPV6){
            strcat(resume, "IPv6");
            const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + offset); //en-tête IPv6
            offset += sizeof(struct ip6_hdr);

            //analyse protocole transport
            //UDP
            if(ip6->ip6_nxt == IPPROTO_UDP){
                strcat(resume, " | UDP");
                const struct udphdr *udp = (const struct udphdr *)(packet + offset);
                uint16_t src_port = ntohs(udp->source);
                uint16_t dst_port = ntohs(udp->dest);
                if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68){
                    strcat(resume, " | BOOTP/DHCP");
                }
            }
        }
        //ARP
        else if (ethertype == ETHERTYPE_ARP){
            strcat(resume, "ARP");
        }
        //Affichage résumé
        printf("%s | len: %u\n", resume, header->len);
    }

    //Niveau 2 et 3 
    printf("\nPaquet %d - %u octets capturés\n", packet_count, header->len);
    int indent = 0;
    int offset = 0;
    uint16_t ethertype;

    //Analyse Ethernet
    offset = parse_ethernet(packet, header->len, verbosity, indent, &ethertype);
    indent += 2; // augmentation de l'indentation pour les prochaines couches

    //Analyse ARP (Layer 2, terminaison)
    if(ethertype == ETHERTYPE_ARP){
        parse_arp(packet + offset, header->len - offset, verbosity, indent);
    }
    //Analyse IPv4 ou IPv6
    else if(ethertype == ETHERTYPE_IP){
        uint8_t proto;
        int ip_hdr_len = parse_ipv4(packet + offset, header->len - offset, verbosity, indent, &proto);
        offset += ip_hdr_len;
        indent += 2;
        //Analyse protocole transport
        //UDP
        if(proto == IPPROTO_UDP){
            uint16_t src_port, dst_port;
            int udp_len = parse_udp(packet + offset, header->len - offset, verbosity, indent, &src_port, &dst_port);
            offset += udp_len;
            indent += 2;
            //BOOTP/DHCP
            if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68){
                parse_dhcp(packet + offset, header->len - offset, verbosity, indent);
            }
        }
    }
    else if (ethertype == ETHERTYPE_IPV6){
        uint8_t next_header;
        int ip6_hdr_len = parse_ipv6(packet + offset, header->len - offset, verbosity, indent, &next_header);
        offset += ip6_hdr_len;
        indent += 2;
        //Analyse protocole transport
        //UDP
        if(next_header == IPPROTO_UDP){
            uint16_t src_port, dst_port;
            int udp_len = parse_udp(packet + offset, header->len - offset, verbosity, indent, &src_port, &dst_port);
            offset += udp_len;
            indent += 2;
            //BOOTP/DHCP
            if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68){
                parse_dhcp(packet + offset, header->len - offset, verbosity, indent);
            }
        }
    }
}
/**

 * Parsing des messages DHCP conformément aux RFCs :
 * - RFC 2131 et RFC 2132 : Spécification du protocole DHCP
 * 
 * Ports UDP : 67 (serveur), 68 (client)
 * 
 *  on utilise l'en-tête BOOTP étendu par les options DHCP et l en-tête DHCP
 */

#include "dhcp.h"
#include "bootp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/textutils.h"
#include "../util/safe_string.h"


/**
 * Convertit un type de message DHCP en chaîne lisible
 * @param msg_type Code numérique du type de message DHCP (1-8)
 * @return Chaîne de caractères représentant le type, ou "Unknown"
 */
const char* dhcp_msg_type_to_str(uint8_t msg_type) {
    switch(msg_type) {
        case DHCP_DISCOVER: return "DISCOVER";
        case DHCP_OFFER:    return "OFFER";
        case DHCP_REQUEST:  return "REQUEST";
        case DHCP_DECLINE:  return "DECLINE";
        case DHCP_ACK:      return "ACK";
        case DHCP_NAK:      return "NAK";
        case DHCP_RELEASE:  return "RELEASE";
        case DHCP_INFORM:   return "INFORM";
        default:            return "Unknown";
    }
}

//parsing principal des messages DHCP/BOOTP

int parse_dhcp(const u_char *packet, int length, int verbosity, int indent){
    if(length < DHCP_FIXED_LEN){
        fprintf(stderr, "BOOTP/DHCP: Packet too short for header (need %d, got %d)\n",
                DHCP_FIXED_LEN, length);
        return 0;
    }
    
    // Détection BOOTP vs DHCP basée sur le magic cookie
    int is_dhcp = 0;
    if(length >= DHCP_FIXED_LEN + 4) {
        uint32_t magic_cookie = ntohl(*(uint32_t *)(packet + DHCP_FIXED_LEN));
        is_dhcp = (magic_cookie == DHCP_MAGIC_COOKIE);
    }
    
    //interpetation de l'en-tête BOOTP
    const Bootp_t *dhcp = (const Bootp_t *)packet;
    uint8_t op = dhcp->bp_op; 
    uint32_t xid = ntohl(dhcp->bp_id); // Transaction ID
    uint16_t secs = ntohs(dhcp->bp_secs); // Secondes depuis le démarrage
    uint16_t flags = ntohs(dhcp->bp_flags); 

    //extraction des adresses IPv4
    char ciaddr_str[INET_ADDRSTRLEN];
    char yiaddr_str[INET_ADDRSTRLEN];
    char siaddr_str[INET_ADDRSTRLEN];
    char giaddr_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    
    //adresse client (ciaddr)
    addr.s_addr = dhcp->bp_ciaddr;
    inet_ntop(AF_INET, &addr, ciaddr_str, sizeof(ciaddr_str));

    //adresse 'your' (yiaddr)
    addr.s_addr = dhcp->bp_yiaddr;
    inet_ntop(AF_INET, &addr, yiaddr_str, sizeof(yiaddr_str));

    //adresse server (siaddr)
    addr.s_addr = dhcp->bp_siaddr;
    inet_ntop(AF_INET, &addr, siaddr_str, sizeof(siaddr_str));

    //adresse gateway (giaddr)
    addr.s_addr = dhcp->bp_giaddr;
    inet_ntop(AF_INET, &addr, giaddr_str, sizeof(giaddr_str));

    //formatage de l'adresse MAC
    char mac[18];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            dhcp->bp_chaddr[0], dhcp->bp_chaddr[1], dhcp->bp_chaddr[2],
            dhcp->bp_chaddr[3], dhcp->bp_chaddr[4], dhcp->bp_chaddr[5]);
    
    //verbosite niveau 2
    if(verbosity == 2){
        if(!is_dhcp) {
            // BOOTP pur (pas de magic cookie DHCP)
            print_indent(indent);
            printf("BOOTP: Op=%s, Xid=0x%08x, YourIP=%s, ServerIP=%s, MAC=%s\n",
                   (op == OP_BOOTREQUEST) ? "Request" : "Reply",
                   xid, yiaddr_str, siaddr_str, mac);
        } else {
            //recherche du type de message DHCP dans les options
            const u_char *optptr = packet + DHCP_FIXED_LEN; //pointeur vers les options
            int longeur_reste = length - DHCP_FIXED_LEN; // longueur restante des options
            const char *msg_type_str = "Inconnu";
            
            optptr += 4;
            longeur_reste -= 4;
            while(longeur_reste > 0){
                uint8_t type = *optptr++;
                if(type == DHCP_OPTION_END) break;
                if(type == 0){ //option de bourrage
                    longeur_reste--;
                    continue;
                }
                uint8_t len = *optptr++;
                longeur_reste -= 2;
                if(type == DHCP_OPTION_MSG_TYPE && len == 1){
                    uint8_t msg_type = *optptr;
                    msg_type_str = dhcp_msg_type_to_str(msg_type);  // conversion en chaîne avec fonction dédiée
                    break; // type de message trouvé
                }
                optptr += len;
                if (longeur_reste < len) break;
                longeur_reste -= len;
            }
            //affichage résumé
            print_indent(indent);
            printf("DHCP: Message=%s, Xid=0x%08x, YourIP=%s, ServerIP=%s, MAC=%s\n",
                    msg_type_str, xid, yiaddr_str, siaddr_str, mac);
        }
    }

    //verbosite niveau 3
    else if (verbosity == 3) {
        // Afficher BOOTP ou DHCP selon le magic cookie
        printf("%*s[L7] %s Header:\n", indent, "", is_dhcp ? "DHCP" : "BOOTP");
        printf("%*s      Operation: %s (%u)\n", indent, "",
               (op == OP_BOOTREQUEST) ? "BootRequest" :
               (op == OP_BOOTREPLY)   ? "BootReply"   : "Inconnu", op);
        printf("%*s      Transaction ID: 0x%08x\n", indent, "", xid);
        printf("%*s      Seconds elapsed: %u\n", indent, "", secs);
        printf("%*s      Flags: 0x%04x (%s)\n", indent, "", flags,(flags & 0x8000) ? "Broadcast" : "Unicast");
        printf("%*s      Client IP: %s\n", indent, "", ciaddr_str);
        printf("%*s      Your IP:   %s\n", indent, "", yiaddr_str);
        printf("%*s      Server IP: %s\n", indent, "", siaddr_str);
        printf("%*s      Relay IP:  %s\n", indent, "", giaddr_str);
        printf("%*s      Client MAC: %s\n", indent, "", mac);

        //sname et file si present
        if(dhcp->bp_sname[0]){
            printf("%*s  Server Name: %.64s\n", indent, "", dhcp->bp_sname);
        }
        if(dhcp->bp_file[0]){
            printf("%*s  Boot File:   %.128s\n", indent, "", dhcp->bp_file);
        }

        //magic cookie (DHCP uniquement)
        if(is_dhcp) {
            const u_char *optptr = packet + DHCP_FIXED_LEN; //pointeur vers les options
            int longeur_reste = length - DHCP_FIXED_LEN; // longueur restante des options
            uint32_t magic_cookie = ntohl(*(uint32_t *)optptr);
                printf("%*s Magic Cookie: 0x%08x\n", indent, "", magic_cookie);
                optptr += 4;
                longeur_reste -= 4;
                printf("%*s Options DHCP:\n", indent, "");
                while(longeur_reste > 0){
                    uint8_t type = *optptr++;
                    if(type == DHCP_OPTION_END) {
                        printf("%*s  Option: End (255)\n", indent, "");
                        break;
                    }
                    if(type == 0){ //option de bourrage
                        longeur_reste--;
                        continue;
                    }
                    if(longeur_reste < 1) break;
                    uint8_t len = *optptr++;
                    longeur_reste -= 2;
                    if(longeur_reste < len) break;

                    //lire les données de l'option
                    switch(type){
                        case DHCP_OPTION_MSG_TYPE:
                            if(len == 1){
                                uint8_t msg_type = *optptr;
                                printf("%*s    Message Type: %s (%u)\n", indent, "", dhcp_msg_type_to_str(msg_type), msg_type);
                            }
                            break;
                        case DHCP_OPTION_SUBNET_MASK:
                            if (len == 4) {
                                struct in_addr mask;
                                char addr_str[INET_ADDRSTRLEN];
                                memcpy(&mask.s_addr, optptr, 4);
                                inet_ntop(AF_INET, &mask, addr_str, sizeof(addr_str));
                                printf("%*s    Subnet Mask: %s\n", indent, "", addr_str);
                            }
                            break;
                        case DHCP_OPTION_ROUTER:
                        case DHCP_OPTION_DNS:
                        case DHCP_OPTION_SERVER_ID:
                        case DHCP_OPTION_REQUESTED_IP:
                            {
                                //adresses IPv4
                                char addr_str[INET_ADDRSTRLEN];
                                int count = len / 4;
                                printf("%*s    %s:", indent, "",
                                    (type == DHCP_OPTION_ROUTER) ? "Router" :
                                    (type == DHCP_OPTION_DNS) ? "DNS Server" :
                                    (type == DHCP_OPTION_SERVER_ID) ? "Server Identifier" :
                                    (type == DHCP_OPTION_REQUESTED_IP) ? "Requested IP Address" : "Unknown");
                                //affichage de toutes les adresses
                                for (int i =0; i < count; i++){
                                    struct in_addr ipaddr;
                                    memcpy(&ipaddr.s_addr, optptr + i*4, 4);
                                    inet_ntop(AF_INET, &ipaddr, addr_str, sizeof(addr_str));
                                    printf(" %s", addr_str);
                                    if(i < count -1) printf(", ");
                                }
                                printf("\n");
                            }
                            break;
                        case DHCP_OPTION_LEASE_TIME:
                        case DHCP_OPTION_RENEWAL_TIME:
                        case DHCP_OPTION_REBINDING_TIME:
                            if (len == 4) {
                                uint32_t t = ntohl(*(const uint32_t *)optptr);
                                const char *label = (type == DHCP_OPTION_LEASE_TIME) ? "IP Address Lease Time" :
                                                    (type == DHCP_OPTION_RENEWAL_TIME) ? "Renewal (T1) Time" :
                                                    (type == DHCP_OPTION_REBINDING_TIME) ? "Rebinding (T2) Time" : "Unknown";
                                printf("%*s    %s: %u seconds\n", indent, "", label, t);
                            }
                            break;
                        case DHCP_OPTION_HOSTNAME:
                            if (len > 0) {
                                char name[256];
                                memcpy(name, optptr, len);
                                name[len] = '\0';
                                printf("%*s    Hostname: %s\n", indent, "", name);
                            }
                            break;
                        case DHCP_OPTION_DOMAIN_NAME:
                            if (len > 0) {
                                char domain[256];
                                memcpy(domain, optptr, len);
                                domain[len] = '\0';
                                printf("%*s    Domain Name: %s\n", indent, "", domain);
                            }
                            break;
                        case DHCP_OPTION_BROADCAST:
                            if (len == 4) {
                                struct in_addr broadcast;
                                char addr_str[INET_ADDRSTRLEN];
                                memcpy(&broadcast.s_addr, optptr, 4);
                                inet_ntop(AF_INET, &broadcast, addr_str, sizeof(addr_str));
                                printf("%*s    Broadcast Address: %s\n", indent, "", addr_str);
                            }
                            break;
                        case DHCP_OPTION_MAX_MSG_SIZE:
                            if (len == 2) {
                                uint16_t max_size = ntohs(*(const uint16_t *)optptr);
                                printf("%*s    Maximum DHCP Message Size: %u bytes\n", indent, "", max_size);
                            }
                            break;
                        case DHCP_OPTION_CLIENT_ID:
                            if (len > 0) {
                                printf("%*s    Client Identifier: ", indent, "");
                                // Format: hardware type (1 byte) + identifier
                                if (len >= 1) {
                                    uint8_t hw_type = optptr[0];
                                    printf("Type=%u ", hw_type);
                                    for(int i = 1; i < len; i++) {
                                        printf("%02x", optptr[i]);
                                    }
                                } else {
                                    for(int i = 0; i < len; i++) {
                                        printf("%02x", optptr[i]);
                                    }
                                }
                                printf("\n");
                            }
                            break;
                        case DHCP_OPTION_PARAM_LIST:
                            if (len > 0) {
                                printf("%*s    Param List: ", indent, "");
                                for(int i=0; i<len; i++) {
                                    printf("%u", optptr[i]);
                                    if (i < len-1) printf(", ");
                                }
                                printf("\n");
                            }
                            break;
                        default:
                            //option non gérée: afficher en hexadécimal
                            {
                                int i;
                                printf("%*s    Option %u: ", indent, "", type);
                                for (i = 0; i < len; i++)
                                    printf("%02x", optptr[i]);
                                printf("\n");
                            }
                            break;
                    }
                    optptr += len;
                    longeur_reste -= len;
                }
        } else {
            // BOOTP pur
            printf("%*s  (BOOTP pur - pas d'options DHCP)\n", indent, "");
        }
    }

    return length;
}

// Génération d'un résumé pour la verbosité 1

int dhcp_v1_summary(const u_char *packet, int caplen, int offset_udp_payload, char *resume){
    if(caplen < offset_udp_payload + DHCP_FIXED_LEN + 4) return 0;
    const Bootp_t *bootp = (const Bootp_t *)(packet + offset_udp_payload);
    uint32_t cookie = ntohl(*(uint32_t*)bootp->bp_vend);
    
    // Formatage de l'adresse MAC
    char mac[18];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            bootp->bp_chaddr[0], bootp->bp_chaddr[1], bootp->bp_chaddr[2],
            bootp->bp_chaddr[3], bootp->bp_chaddr[4], bootp->bp_chaddr[5]);
    
    // distinguer BOOTP pur et DHCP
    if(cookie != DHCP_MAGIC_COOKIE){
        // Pure BOOTP
        safe_strcat(resume, " BOOTP", RESUME_BUFFER_SIZE);
        if(bootp->bp_op == OP_BOOTREQUEST) {
            safe_strcat(resume, " Request", RESUME_BUFFER_SIZE);
        } else if(bootp->bp_op == OP_BOOTREPLY) {
            safe_strcat(resume, " Reply", RESUME_BUFFER_SIZE);
        }
        safe_strcat(resume, " ", RESUME_BUFFER_SIZE);
        safe_strcat(resume, mac, RESUME_BUFFER_SIZE);
        return 1;
    }
    
    // trouver le type de message DHCP et l'adresse IP demandée
    const u_char *p = bootp->bp_vend + 4;
    int remain = caplen - (offset_udp_payload + DHCP_FIXED_LEN + 4);
    const char *type_str = "Unknown";  // type de message par défaut
    char requested_ip[INET_ADDRSTRLEN] = "";
    char client_ip[INET_ADDRSTRLEN] = "";
    
    // Options parsing pour type de message et adresse IP demandée
    while(remain > 2){
        uint8_t code = *p++;
        if(code == DHCP_OPTION_END) break;
        if(code == 0){ remain--; continue; }
        uint8_t len = *p++;
        remain -= 2;
        if(remain < len) break;
        
        if(code == DHCP_OPTION_MSG_TYPE && len == 1){
            uint8_t mt = *p;
            type_str = dhcp_msg_type_to_str(mt);
        }
        else if(code == DHCP_OPTION_REQUESTED_IP && len == 4){
            struct in_addr addr;
            memcpy(&addr.s_addr, p, 4);
            inet_ntop(AF_INET, &addr, requested_ip, sizeof(requested_ip));
        }
        
        p += len;
        remain -= len;
    }
    
    // verifier si l'adresse client est présente
    if(bootp->bp_ciaddr != 0){
        struct in_addr addr;
        addr.s_addr = bootp->bp_ciaddr;
        inet_ntop(AF_INET, &addr, client_ip, sizeof(client_ip));
    }
    
    // resume construction
    safe_strcat(resume, " ", RESUME_BUFFER_SIZE);
    safe_strcat(resume, type_str, RESUME_BUFFER_SIZE);
    safe_strcat(resume, " ", RESUME_BUFFER_SIZE);
    safe_strcat(resume, mac, RESUME_BUFFER_SIZE);
    
    // Ajout des adresses IP et MAC pertinentes
    if(strlen(requested_ip) > 0){
        safe_strcat(resume, " req:", RESUME_BUFFER_SIZE);
        safe_strcat(resume, requested_ip, RESUME_BUFFER_SIZE);
    } else if(strlen(client_ip) > 0){
        safe_strcat(resume, " from:", RESUME_BUFFER_SIZE);
        safe_strcat(resume, client_ip, RESUME_BUFFER_SIZE);
    } else if(bootp->bp_yiaddr != 0){
        // montrer l'adresse 'your' si présente
        struct in_addr addr;
        addr.s_addr = bootp->bp_yiaddr;
        char yiaddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, yiaddr, sizeof(yiaddr));
        safe_strcat(resume, " offer:", RESUME_BUFFER_SIZE);
        safe_strcat(resume, yiaddr, RESUME_BUFFER_SIZE);
    }
    
    return 1;
}
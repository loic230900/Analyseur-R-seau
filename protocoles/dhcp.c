#include "dhcp.h"
#include "bootp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void parse_dhcp(const u_char *packet, int length, int verbosity, int indent){
    if(length < DHCP_FIXED_LEN){
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un message DHCP complet.\n");
        return;
    }
    //interpetation de l'en-tête BOOTP
    const Bootp_t *dhcp = (const Bootp_t *)packet;
    uint8_t op = dhcp->bp_op; 
    uint32_t xid = ntohl(dhcp->bp_id); // Transaction ID
    uint16_t secs = ntohs(dhcp->bp_secs); // Secondes depuis le démarrage
    uint16_t flags = ntohs(dhcp->bp_flags); 

    //extraction des addresses IPv4
    struct in_addr addr;
    char addr_str[INET_ADDRSTRLEN];
    
        //address client (ciaddr)
    addr.s_addr = dhcp->bp_ciaddr;
    inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
    char ciaddr_str[INET_ADDRSTRLEN];
    strcpy(ciaddr_str, addr_str);

        //address 'your' (yiaddr)
    addr.s_addr = dhcp->bp_yiaddr;
    inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
    char yiaddr_str[INET_ADDRSTRLEN];
    strcpy(yiaddr_str, addr_str);

        //address server (siaddr)
    addr.s_addr = dhcp->bp_siaddr;
    inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
    char siaddr_str[INET_ADDRSTRLEN];
    strcpy(siaddr_str, addr_str);

        //address gateway (giaddr)
    addr.s_addr = dhcp->bp_giaddr;
    inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
    char giaddr_str[INET_ADDRSTRLEN];
    strcpy(giaddr_str, addr_str);

    //formatage de l'adresse MAC
    char mac[18];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            dhcp->bp_chaddr[0], dhcp->bp_chaddr[1], dhcp->bp_chaddr[2],
            dhcp->bp_chaddr[3], dhcp->bp_chaddr[4], dhcp->bp_chaddr[5]);
    
    //verbosite niveau 2
    if(verbosity == 2){
        //recherche du type de message DHCP dans les options
        const u_char *optptr = packet + DHCP_FIXED_LEN; //pointeur vers les options
        int longeur_reste = length - DHCP_FIXED_LEN; // longueur restante des options
        const char *msg_type_str = "Inconnu";
        
        if(longeur_reste >= 4){
            uint32_t magic_cookie = ntohl(*(uint32_t *)optptr);
            if(magic_cookie == DHCP_MAGIC_COOKIE){
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
                        switch(msg_type){
                            case DHCP_DISCOVER: msg_type_str = "DISCOVER"; break;
                            case DHCP_OFFER:    msg_type_str = "OFFER";    break;
                            case DHCP_REQUEST:  msg_type_str = "REQUEST";  break;
                            case DHCP_DECLINE:  msg_type_str = "DECLINE";  break;
                            case DHCP_ACK:      msg_type_str = "ACK";      break;
                            case DHCP_NAK:      msg_type_str = "NAK";      break;
                            case DHCP_RELEASE:  msg_type_str = "RELEASE";  break;
                            default:            msg_type_str = "Inconnu";  break;
                        }
                        break; // type de message trouvé
                    }
                    optptr += len;
                    if (longeur_reste < len) break;
                    longeur_reste -= len;
                }
            }
        }
        //affichage résumé
        for(int i = 0; i < indent; i++) printf(" ");
        printf("DHCP: Message=%s, Xid=0x%08x, YourIP=%s, ServerIP=%s, MAC=%s\n",
                msg_type_str, xid, yiaddr_str, siaddr_str, mac);
    }

    //verbosite niveau 3
    else if (verbosity == 3) {
        printf("%*sDHCP:\n", indent, "");
        printf("%*s  Operation: %s (%u)\n", indent, "",
               (op == OP_BOOTREQUEST) ? "BootRequest" :
               (op == OP_BOOTREPLY)   ? "BootReply"   : "Unknown", op);
        printf("%*s  Transaction ID: 0x%08x\n", indent, "", xid);
        printf("%*s  Seconds elapsed: %u\n", indent, "", secs);
        printf("%*s  Flags: 0x%04x (%s)\n", indent, "", flags,(flags & 0x8000) ? "Broadcast" : "Unicast");
        printf("%*s  Client IP: %s\n", indent, "", ciaddr_str);
        printf("%*s  Your IP:   %s\n", indent, "", yiaddr_str);
        printf("%*s  Server IP: %s\n", indent, "", siaddr_str);
        printf("%*s  Relay IP:  %s\n", indent, "", giaddr_str);
        printf("%*s  Client MAC: %s\n", indent, "", mac);

        //sname et file si present
        if(dhcp->bp_sname[0]){
            printf("%*s  Server Name: %.64s\n", indent, "", dhcp->bp_sname);
        }
        if(dhcp->bp_file[0]){
            printf("%*s  Boot File:   %.128s\n", indent, "", dhcp->bp_file);
        }

        //magic cookie 
        const u_char *optptr = packet + DHCP_FIXED_LEN; //pointeur vers les options
        int longeur_reste = length - DHCP_FIXED_LEN; // longueur restante des options
        if(longeur_reste >= 4){
            uint32_t magic_cookie = ntohl(*(uint32_t *)optptr);
            if(magic_cookie == DHCP_MAGIC_COOKIE){
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
                                const char *msg_type_str = "Inconnu";
                                switch(msg_type){
                                    case DHCP_DISCOVER: msg_type_str = "DISCOVER"; break;
                                    case DHCP_OFFER:    msg_type_str = "OFFER";    break;
                                    case DHCP_REQUEST:  msg_type_str = "REQUEST";  break;
                                    case DHCP_DECLINE:  msg_type_str = "DECLINE";  break;
                                    case DHCP_ACK:      msg_type_str = "ACK";      break;
                                    case DHCP_NAK:      msg_type_str = "NAK";      break;
                                    case DHCP_RELEASE:  msg_type_str = "RELEASE";  break;
                                }
                                printf("%*s    Message Type: %s (%u)\n", indent, "", msg_type_str, msg_type);
                            }
                            break;
                        case DHCP_OPTION_SUBNET_MASK:
                            if (len == 4) {
                                struct in_addr mask;
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
                                int count = len / 4;
                                printf("%*s    %s:", indent, "",
                                    (type == DHCP_OPTION_ROUTER) ? "Router" :
                                    (type == DHCP_OPTION_DNS) ? "DNS Server" :
                                    (type == DHCP_OPTION_SERVER_ID) ? "Server Identifier" :
                                    (type == DHCP_OPTION_REQUESTED_IP) ? "Requested IP Address" : "Unknown");
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
            }
        }
    }
}

int dhcp_v1_summary(const u_char *packet, int caplen, int offset_udp_payload, char *resume){
    if(caplen < offset_udp_payload + DHCP_FIXED_LEN + 4) return 0;
    const Bootp_t *bootp = (const Bootp_t *)(packet + offset_udp_payload);
    uint32_t cookie = ntohl(*(uint32_t*)bootp->bp_vend);
    if(cookie != DHCP_MAGIC_COOKIE){
        if(strlen(resume)<240) strcat(resume, " NoCookie");
        return 1;
    }
    const u_char *p = bootp->bp_vend + 4;
    int remain = caplen - (offset_udp_payload + DHCP_FIXED_LEN + 4);
    while(remain > 2){
        uint8_t code = *p++;
        if(code == DHCP_OPTION_END) break;
        if(code == 0){ remain--; continue; }
        uint8_t len = *p++;
        remain -= 2;
        if(remain < len) break;
        if(code == DHCP_OPTION_MSG_TYPE && len == 1){
            uint8_t mt = *p;
            if(strlen(resume)<240){
                switch(mt){
                    case DHCP_DISCOVER: strcat(resume," Discover"); break;
                    case DHCP_OFFER: strcat(resume," Offer"); break;
                    case DHCP_REQUEST: strcat(resume," Request"); break;
                    case DHCP_DECLINE: strcat(resume," Decline"); break;
                    case DHCP_ACK: strcat(resume," ACK"); break;
                    case DHCP_NAK: strcat(resume," NAK"); break;
                    case DHCP_RELEASE: strcat(resume," Release"); break;
                    default: { char tmp[16]; snprintf(tmp,sizeof(tmp)," Type%u",mt); strcat(resume,tmp); }
                }
            }
            break;
        }
        p += len;
        remain -= len;
    }
    return 1;
}
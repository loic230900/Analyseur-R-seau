/**
 * Module de détection des protocoles applicatifs
 * 
 * Détection basée sur les ports source/destination.
 * Approche table-driven pour éviter la duplication.
 */

#include "detection.h"
#include "capture.h"
#include "protocoles.h"


/* Table des services TCP avec leurs ports et noms */
static const struct {
    uint16_t port1;
    uint16_t port2;  /* 0 si un seul port */
    app_proto_tcp_t proto;
    const char *name;
} tcp_services[] = {
    {DNS_PORT, 0, APP_PROTO_TCP_DNS, "dns"},
    {HTTP_PORT_PLAIN, 0, APP_PROTO_TCP_HTTP, "http"},
    {HTTPS_PORT, 0, APP_PROTO_TCP_HTTPS, "https"},
    {SMTP_PORT_PLAIN, SMTP_PORT_SUBMISSION, APP_PROTO_TCP_SMTP, "smtp"},
    {SMTP_PORT_SSL, 0, APP_PROTO_TCP_SMTPS, "smtps"},
    {IMAP_PORT_PLAIN, 0, APP_PROTO_TCP_IMAP, "imap"},
    {IMAP_PORT_SSL, 0, APP_PROTO_TCP_IMAPS, "imaps"},
    {POP3_PORT_PLAIN, 0, APP_PROTO_TCP_POP3, "pop3"},
    {POP3_PORT_SSL, 0, APP_PROTO_TCP_POP3S, "pop3s"},
    {FTP_PORT_CONTROL, 0, APP_PROTO_TCP_FTP, "ftp"},
    {FTP_PORT_DATA, 0, APP_PROTO_TCP_FTP_DATA, "ftp-data"},
    {TELNET_PORT, 0, APP_PROTO_TCP_TELNET, "telnet"}
};
#define TCP_SERVICES_COUNT (sizeof(tcp_services) / sizeof(tcp_services[0]))

/* Table des services UDP avec leurs ports et noms */
static const struct {
    uint16_t port1;
    uint16_t port2;  /* 0 si un seul port */
    app_proto_udp_t proto;
    const char *name;
} udp_services[] = {
    {DNS_PORT, 0, APP_PROTO_UDP_DNS, "dns"},
    {5353, 0, APP_PROTO_UDP_DNS, "mdns"},  /* mDNS réutilise parser DNS */
    {DHCP_SERVER_PORT, DHCP_CLIENT_PORT, APP_PROTO_UDP_DHCP, "dhcp"},
    {HTTPS_PORT, 0, APP_PROTO_UDP_QUIC, "quic"}
};
#define UDP_SERVICES_COUNT (sizeof(udp_services) / sizeof(udp_services[0]))

/* Helper: vérifie si un port correspond à une entrée de table */
static int port_matches(uint16_t src, uint16_t dst, uint16_t p1, uint16_t p2) {
    if (src == p1 || dst == p1) return 1;
    if (p2 != 0 && (src == p2 || dst == p2)) return 1;
    return 0;
}


/**
 * Détecte le protocole applicatif TCP basé sur les ports.
 * Ignore les paquets sans payload (SYN/ACK/FIN).
 * 
 * @param src_port    Port source TCP.
 * @param dst_port    Port destination TCP.
 * @param payload_len Longueur du payload TCP.
 * @return Protocole détecté ou APP_PROTO_TCP_NONE.
 */
app_proto_tcp_t detect_app_tcp(uint16_t src_port, uint16_t dst_port, int payload_len) {
    if (payload_len <= 0) return APP_PROTO_TCP_NONE;
    
    for (size_t i = 0; i < TCP_SERVICES_COUNT; i++) {
        if (port_matches(src_port, dst_port, tcp_services[i].port1, tcp_services[i].port2)) {
            return tcp_services[i].proto;
        }
    }
    return APP_PROTO_TCP_NONE;
}

/**
 * Détecte le protocole applicatif UDP basé sur les ports.
 * 
 * @param src_port  Port source UDP.
 * @param dst_port  Port destination UDP.
 * @return Protocole détecté ou APP_PROTO_UDP_NONE.
 * 
 */
app_proto_udp_t detect_app_udp(uint16_t src_port, uint16_t dst_port) {
    for (size_t i = 0; i < UDP_SERVICES_COUNT; i++) {
        if (port_matches(src_port, dst_port, udp_services[i].port1, udp_services[i].port2)) {
            return udp_services[i].proto;
        }
    }
    return APP_PROTO_UDP_NONE;
}


/**
 * Retourne le nom du service TCP pour annoter les paquets sans payload.
 * 
 * @param src_port  Port source TCP.
 * @param dst_port  Port destination TCP.
 * @return Nom du service ou NULL si inconnu.
 * 
 */
const char* get_tcp_service_name(uint16_t src_port, uint16_t dst_port) {
    for (size_t i = 0; i < TCP_SERVICES_COUNT; i++) {
        if (port_matches(src_port, dst_port, tcp_services[i].port1, tcp_services[i].port2)) {
            return tcp_services[i].name;
        }
    }
    return NULL;
}

/**
 * Retourne le nom du service UDP.
 * 
 * @param src_port  Port source UDP.
 * @param dst_port  Port destination UDP.
 * @return Nom du service ou NULL si inconnu.
 * 
 */
const char* get_udp_service_name(uint16_t src_port, uint16_t dst_port) {
    for (size_t i = 0; i < UDP_SERVICES_COUNT; i++) {
        if (port_matches(src_port, dst_port, udp_services[i].port1, udp_services[i].port2)) {
            return udp_services[i].name;
        }
    }
    return NULL;
}

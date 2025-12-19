/**
* Définitions portables pour BOOTP/DHCP (parsing en espace utilisateur)
 * 
 * Structures et constantes pour le parsing BOOTP (RFC 951) et DHCP (RFC 2131).
 * Définit les structures de paquets BOOTP, magic cookie DHCP et options.
 * Ports UDP : 67 (serveur), 68 (client).
 * 
 * 
 * Fichier inspiré de: https://android.googlesource.com/device/ti/bootloader/uboot/+/master/net/bootp.h?autodive=0%2F
 */

/* Portable BOOTP/DHCP header for user-space packet parsing. */
#ifndef __BOOTP_H__
#define __BOOTP_H__

#include <stdint.h>
#include <netinet/in.h>

/* RFC 2131 recommends a minimum DHCP options area of 312 bytes. */
#ifndef OPT_SIZE
#define OPT_SIZE 312
#endif

/* 32-bit IPv4 address container */
typedef uint32_t IPaddr_t;

#define DHCP_MAGIC_COOKIE 0x63825363  /* 99.130.83.99 in network byte order */
#define DHCP_OPTION_END       255
#define DHCP_OPTION_MSG_TYPE  53
#define DHCP_OPTION_SUBNET_MASK     1
#define DHCP_OPTION_ROUTER          3
#define DHCP_OPTION_DNS             6
#define DHCP_OPTION_HOSTNAME        12
#define DHCP_OPTION_DOMAIN_NAME     15
#define DHCP_OPTION_BROADCAST       28
#define DHCP_OPTION_REQUESTED_IP    50
#define DHCP_OPTION_LEASE_TIME      51
#define DHCP_OPTION_SERVER_ID       54
#define DHCP_OPTION_PARAM_LIST      55
#define DHCP_OPTION_MAX_MSG_SIZE    57
#define DHCP_OPTION_RENEWAL_TIME    58
#define DHCP_OPTION_REBINDING_TIME  59
#define DHCP_OPTION_CLIENT_ID       61

/* Fixed-length portion of BOOTP/DHCP header (op through file) */
#define DHCP_FIXED_LEN 236

/* En-tête fixe BOOTP/DHCP (RFC 951 / 2131) */
typedef struct Bootp_s {
	uint8_t   bp_op;       /* Opération : 1=requête, 2=réponse */
#define OP_BOOTREQUEST 1
#define OP_BOOTREPLY   2
	uint8_t   bp_htype;    /* Type matériel (1=Ethernet) */
#define HWT_ETHER      1
	uint8_t   bp_hlen;     /* Longueur adresse matérielle (6 pour Ethernet) */
#define HWL_ETHER      6
	uint8_t   bp_hops;     /* Nombre de sauts relais */
	uint32_t  bp_id;       /* Identifiant de transaction */
	uint16_t  bp_secs;     /* Secondes depuis le démarrage */
	uint16_t  bp_flags;    /* Drapeaux (bit 0x8000 = broadcast) */
	IPaddr_t  bp_ciaddr;   /* Adresse IP client */
	IPaddr_t  bp_yiaddr;   /* Adresse IP "votre" (client) */
	IPaddr_t  bp_siaddr;   /* Adresse IP serveur */
	IPaddr_t  bp_giaddr;   /* Adresse IP agent relais */
	uint8_t   bp_chaddr[16]; /* Adresse matérielle client */
	char      bp_sname[64];  /* Nom d'hôte serveur optionnel */
	char      bp_file[128];  /* Nom du fichier d'amorçage */
	uint8_t   bp_vend[OPT_SIZE]; /* Zone spécifique vendeur / options DHCP */
} Bootp_t;

/* Alias rétrocompatibilité si ancien code utilisant bp_spare1 */
#define bp_spare1 bp_flags

#define BOOTP_HDR_SIZE ((int)sizeof(Bootp_t))

/* Structure alternative utilisant in_addr standard (utile pour inet_ntop) */
struct dhcp_packet {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    uint8_t  chaddr[16];
    char     sname[64];
    char     file[128];
    uint8_t  options[OPT_SIZE];
} __attribute__((packed));

typedef enum {
	INIT,
	INIT_REBOOT,
	REBOOTING,
	SELECTING,
	REQUESTING,
	REBINDING,
	BOUND,
	RENEWING
} dhcp_state_t;

// Types de messages DHCP
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7
#define DHCP_INFORM   8

/* Milliseconds to wait for offers */
#ifndef SELECT_TIMEOUT
#define SELECT_TIMEOUT 3000U
#endif

#endif /* __BOOTP_H__ */
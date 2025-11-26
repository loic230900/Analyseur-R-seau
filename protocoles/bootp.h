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

/* -------------------- DHCP Magic Cookie & Options -------------------- */
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

/* BOOTP/DHCP fixed header (RFC 951 / 2131) */
typedef struct Bootp_s {
	uint8_t   bp_op;       /* Operation: 1=request, 2=reply */
#define OP_BOOTREQUEST 1
#define OP_BOOTREPLY   2
	uint8_t   bp_htype;    /* Hardware type (1=Ethernet) */
#define HWT_ETHER      1
	uint8_t   bp_hlen;     /* Hardware address length (6 for Ethernet) */
#define HWL_ETHER      6
	uint8_t   bp_hops;     /* Relay hop count */
	uint32_t  bp_id;       /* Transaction ID */
	uint16_t  bp_secs;     /* Seconds since boot began */
	uint16_t  bp_flags;    /* Flags (bit 0x8000 = broadcast) */
	IPaddr_t  bp_ciaddr;   /* Client IP address */
	IPaddr_t  bp_yiaddr;   /* 'Your' (client) IP address */
	IPaddr_t  bp_siaddr;   /* Server IP address */
	IPaddr_t  bp_giaddr;   /* Relay agent IP address */
	uint8_t   bp_chaddr[16]; /* Client hardware address */
	char      bp_sname[64];  /* Optional server host name */
	char      bp_file[128];  /* Boot file name */
	uint8_t   bp_vend[OPT_SIZE]; /* Vendor-specific area / DHCP options */
} Bootp_t;

/* Backward-compatibility alias if old code used bp_spare1 */
#define bp_spare1 bp_flags

#define BOOTP_HDR_SIZE ((int)sizeof(Bootp_t))

/* Alternative struct using standard in_addr (useful for inet_ntop) */
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

/* -------------------- DHCP definitions-------------------- */
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

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7

/* Milliseconds to wait for offers */
#ifndef SELECT_TIMEOUT
#define SELECT_TIMEOUT 3000U
#endif

#endif /* __BOOTP_H__ */
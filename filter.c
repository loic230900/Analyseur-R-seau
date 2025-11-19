#include "filter.h"
#include <string.h>
#include <stdio.h>
#include "protocoles/dns.h"  /* pour dns_bpf_all() */

const char* filter_translate_alias(const char *user_expr) {
    if (!user_expr) return NULL;
    if (strcmp(user_expr, "dns") == 0 || strcmp(user_expr, "alldns") == 0) {
        return dns_bpf_all();
    }
    if (strcmp(user_expr, "http") == 0) {
        return "tcp port 80";
    }
    return user_expr;
}

int filter_apply(pcap_t *handle,
                 const char *interface,
                 const char *user_expr,
                 char *applied_expr_out,
                 size_t applied_expr_len) {
    if (!user_expr) {
        if (applied_expr_out && applied_expr_len) applied_expr_out[0] = '\0';
        return FILTER_OK; /* pas de filtre demandé */
    }

    const char *translated = filter_translate_alias(user_expr);
    if (applied_expr_out && applied_expr_len) {
        snprintf(applied_expr_out, applied_expr_len, "%s", translated);
    }

    struct bpf_program prog;
    bpf_u_int32 net = 0, mask = 0;
    if (interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Avertissement: lookupnet échoué sur %s: %s\n", interface, errbuf);
            net = 0; mask = 0; /* on continue malgré tout */
        }
    }

    if (pcap_compile(handle, &prog, translated, 0, net) == -1) {
        fprintf(stderr, "Erreur compilation filtre '%s': %s\n", translated, pcap_geterr(handle));
        return FILTER_ERR_COMPILE;
    }
    if (pcap_setfilter(handle, &prog) == -1) {
        fprintf(stderr, "Erreur application filtre '%s': %s\n", translated, pcap_geterr(handle));
        pcap_freecode(&prog);
        return FILTER_ERR_SET;
    }
    pcap_freecode(&prog);
    return FILTER_OK;
}

#ifndef FILTER_H
#define FILTER_H

#include <pcap.h>

/* Codes de retour */
#define FILTER_OK            0
#define FILTER_ERR_COMPILE   1
#define FILTER_ERR_SET       2
#define FILTER_ERR_LOOKUP    3

/* Traduction d'alias simples (ex: "dns") vers expression BPF. */
const char* filter_translate_alias(const char *user_expr);

/*
 * Applique un filtre BPF sur handle.
 * interface: nom interface (NULL si offline)
 * user_expr: expression utilisateur (alias possible)
 * applied_expr_out: buffer pour expression finale (peut être NULL)
 * applied_expr_len: taille buffer
 */
int filter_apply(pcap_t *handle,
                 const char *interface,
                 const char *user_expr,
                 char *applied_expr_out,
                 size_t applied_expr_len);

#endif /* FILTER_H */

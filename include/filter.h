/**
 * Ce fichier déclare les fonctions de gestion des filtres de capture
 * réseau basés sur BPF 
 * 
 * Fonctionnalités :
 * - Traduction d'alias utilisateur en expressions BPF (petit bonus pratique qui a faciliter les tests)
 * - Compilation et application de filtres sur une session pcap
 * 
 * Alias supportés : dns, http, web, smtp, mail, ftp, telnet, all
 */

#ifndef FILTER_H
#define FILTER_H

#include <pcap.h>

//CODES DE RETOUR
#define FILTER_OK            0   // Filtre appliqué avec succès
#define FILTER_ERR_COMPILE   1   // Erreur de compilation du filtre BPF 
#define FILTER_ERR_SET       2   // Erreur d'application du filtre 
#define FILTER_ERR_LOOKUP    3   // Erreur de lookup réseau (non bloquant)

/**
 * Cette fonction convertit un alias court et mémorisable
 * en expression BPF complète. Si l'entrée n'est pas un alias reconnu,
 * elle est retournée telle quelle pour utilisation directe.
 * 
 * @param user_expr Expression utilisateur (alias ou BPF brut)
 * 
 * @return Expression BPF correspondante (ne pas libérer)
 */
const char* filter_translate_alias(const char *user_expr);

/**
 * Cette fonction effectue la traduction de l'alias, la compilation
 * du filtre BPF et son application à la session de capture.
 * 
 * @param handle          Session pcap active
 * @param interface       Nom de l'interface (NULL si fichier offline)
 * @param user_expr       Expression utilisateur (alias ou BPF brut)
 * @param applied_expr_out Buffer pour stocker l'expression traduite (optionnel)
 * @param applied_expr_len Taille du buffer de sortie
 * 
 * @return FILTER_OK si succès, FILTER_ERR_* sinon
 */
int filter_apply(pcap_t *handle, const char *interface, const char *user_expr, char *applied_expr_out, size_t applied_expr_len);

#endif /* FILTER_H */

/**
 * Ce fichier déclare les fonctions d'aide pour l'analyse des protocoles
 * de la couche application basés sur du texte ASCII (HTTP, SMTP, FTP,
 * IMAP, POP3, Telnet).
 * 
 */

#ifndef TEXTUTILS_H
#define TEXTUTILS_H

// typedef u_char si non défini(ce qui etais le cas sur mon systeme ...)
#ifndef UCHAR_TYPEDEF_GUARD // garde contre les redéfinitions
#define UCHAR_TYPEDEF_GUARD
/** Type u_char si non défini */
typedef unsigned char u_char;
#endif

/**
 * Génère le nombre d'espaces spécifié pour l'affichage hiérarchique
 * des protocoles encapsulés (verbosités 2 et 3).
 * 
 * @param indent Nombre d'espaces à afficher (0 = pas d'indentation)
 */
void print_indent(int indent);

/**
 * Recherche la première occurrence d'une terminaison de ligne (CRLF ou LF)
 * à partir de l'offset spécifié. Compatible RFC (CRLF) et Unix (LF).
 * 
 * @param data    Pointeur vers les données à analyser
 * @param offset  Position de départ de la recherche
 * @param max_len Longueur maximale des données
 * 
 * @return Position du premier caractère de terminaison, -1 si non trouvé
 */
int text_find_line_end(const u_char *data, int offset, int max_len);

/**
 * Copie une ligne complète du buffer source vers le buffer destination,
 * en excluant les caractères de terminaison (\r\n ou \n).
 * 
 * @param data    Pointeur vers les données source
 * @param offset  Position de départ de la ligne
 * @param max_len Longueur maximale des données
 * @param out     Buffer de destination pour la ligne extraite
 * @param out_len Taille du buffer de destination
 * 
 * @return Offset de la prochaine ligne, -1 si pas de fin de ligne
 */
int text_extract_line(const u_char *data, int offset, int max_len, char *out, int out_len);


/**
 * Analyse les premiers octets pour déterminer si le contenu est
 * du texte lisible ou des données binaires/chiffrées.
 * 
 * Critères :
 * - Analyse au maximum 128 premiers octets
 * - Retourne vrai si >80% de caractères imprimables
 * - Retourne faux si caractères de contrôle suspects trouvés
 * 
 * @param data Pointeur vers les données à analyser
 * @param len  Longueur des données disponibles
 * 
 * @return 1 si texte imprimable (>80%), 0 sinon
 */
int text_is_printable(const u_char *data, int len);

#endif /* TEXTUTILS_H */

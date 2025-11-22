#ifndef TEXTUTILS_H
#define TEXTUTILS_H

#ifndef u_char
typedef unsigned char u_char;
#endif

/**
 * Trouve la fin de ligne (\r\n ou \n) dans les données.
 * Utilisé pour parser les protocoles textuels (HTTP, SMTP, IMAP, etc.)
 * 
 * @param data      Pointeur vers les données
 * @param offset    Offset de départ pour la recherche
 * @param max_len   Longueur maximale des données
 * @return          Offset de la fin de ligne, -1 si non trouvé
 */
int text_find_line_end(const u_char *data, int offset, int max_len);

/**
 * Extrait une ligne des données sans les terminaisons de ligne (\r\n ou \n).
 * 
 * @param data      Pointeur vers les données
 * @param offset    Offset de départ pour l'extraction
 * @param max_len   Longueur maximale des données
 * @param out       Buffer de sortie pour la ligne extraite
 * @param out_len   Taille du buffer de sortie
 * @return          Nouvel offset après la ligne extraite, -1 en cas d'erreur
 */
int text_extract_line(const u_char *data, int offset, int max_len, char *out, int out_len);

/**
 * Vérifie si un bloc de données contient principalement du texte imprimable.
 * Utile pour différencier texte clair vs données chiffrées/binaires.
 * 
 * @param data      Pointeur vers les données
 * @param len       Longueur des données à vérifier
 * @return          1 si texte imprimable (>80%), 0 sinon
 */
int text_is_printable(const u_char *data, int len);

#endif /* TEXTUTILS_H */

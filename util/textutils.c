#include "textutils.h"
#include <ctype.h>

/**
 * Trouve la fin de ligne (\r\n ou \n) dans les données
 */
int text_find_line_end(const u_char *data, int offset, int max_len) {
    // Chercher d'abord \r\n (CRLF - standard RFC)
    for (int i = offset; i < max_len - 1; i++) {
        if (data[i] == '\r' && data[i+1] == '\n')
            return i;
    }
    
    // Sinon chercher juste \n (LF - Unix)
    for (int i = offset; i < max_len; i++) {
        if (data[i] == '\n')
            return i;
    }
    
    return -1;
}

/**
 * Extrait une ligne des données sans les terminaisons de ligne
 */
int text_extract_line(const u_char *data, int offset, int max_len, char *out, int out_len) {
    int end = text_find_line_end(data, offset, max_len);
    if (end < 0)
        return -1;

    int line_len = end - offset;
    if (line_len >= out_len)
        line_len = out_len - 1;
    
    // Copier la ligne sans CRLF/LF
    for (int i = 0; i < line_len; i++) {
        out[i] = data[offset + i];
    }
    out[line_len] = '\0';

    // Avancer après CRLF ou LF
    if (end + 1 < max_len && data[end] == '\r' && data[end+1] == '\n')
        return end + 2;  // Après \r\n
    return end + 1;      // Après \n
}

/**
 * Vérifie si un bloc de données est du texte imprimable
 */
int text_is_printable(const u_char *data, int len) {
    if (len <= 0) 
        return 0;
    
    int printable_count = 0;
    int check_len = (len < 128) ? len : 128; // Vérifier premiers 128 octets max
    
    for (int i = 0; i < check_len; i++) {
        unsigned char c = data[i];
        
        // Caractères acceptables : imprimables + espaces blancs
        if (isprint(c) || c == '\r' || c == '\n' || c == '\t') {
            printable_count++;
        } 
        // Caractères de contrôle suspects (probablement binaire/chiffré)
        else if (c < 32 && c != '\r' && c != '\n' && c != '\t') {
            return 0;
        }
    }
    
    // Au moins 80% de caractères imprimables
    return (printable_count * 100 / check_len) > 80;
}

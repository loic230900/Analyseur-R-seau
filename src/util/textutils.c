/**
 * Utilitaires pour le parsing des protocoles textuels
 * 
 * Ce module fournit des fonctions d'aide pour l'analyse des protocoles
 * de la couche application basés sur du texte (HTTP, SMTP, FTP, IMAP,
 * POP3, Telnet).
 */

#include "textutils.h"
#include <ctype.h>
#include <stdio.h>


// Indente l'affichage de 'indent' espaces

void print_indent(int indent) {
    for(int i = 0; i < indent; i++) {
        printf(" ");
    }
}

// Trouve la fin de ligne dans un bloc de données

int text_find_line_end(const u_char *data, int offset, int max_len) {
    /* Recherche CRLF en priorité (standard RFC) */
    for (int i = offset; i < max_len - 1; i++) {
        if (data[i] == '\r' && data[i+1] == '\n')
            return i;
    }
    
    /* Fallback sur LF seul (Unix) */
    for (int i = offset; i < max_len; i++) {
        if (data[i] == '\n')
            return i;
    }
    
    /* Aucune fin de ligne trouvée */
    return -1;
}

// Extrait une ligne complète du buffer

int text_extract_line(const u_char *data, int offset, int max_len, char *out, int out_len) {
    int end = text_find_line_end(data, offset, max_len);
    if (end < 0)
        return -1;

    /* Calcul de la longueur de la ligne (sans terminaison) */
    int line_len = end - offset;
    if (line_len >= out_len)
        line_len = out_len - 1;  /* Troncature si buffer trop petit */
    
    /* Copie des caractères de la ligne */
    for (int i = 0; i < line_len; i++) {
        out[i] = (char)data[offset + i];
    }
    out[line_len] = '\0';

    /* Calcul de l'offset pour la prochaine ligne */
    if (end + 1 < max_len && data[end] == '\r' && data[end+1] == '\n')
        return end + 2;  /* Après \r\n */
    return end + 1;      /* Après \n seul */
}


// Vérifie si le contenu est du texte imprimable*

int text_is_printable(const u_char *data, int len) {
    if (len <= 0) 
        return 0;
    
    int printable_count = 0;
    int check_len = (len < 128) ? len : 128;  /* Limiter à 128 octets */
    
    for (int i = 0; i < check_len; i++) {
        unsigned char c = data[i];
        
        /* Caractères acceptables : imprimables ASCII + espaces blancs */
        if (isprint(c) || c == '\r' || c == '\n' || c == '\t') {
            printable_count++;
        } 
        /* Caractère de contrôle suspect → probablement binaire/chiffré */
        else if (c < 32 && c != '\r' && c != '\n' && c != '\t') {
            return 0;
        }
    }
    
    /* Seuil de 80% de caractères imprimables */
    return (printable_count * 100 / check_len) > 80;
}

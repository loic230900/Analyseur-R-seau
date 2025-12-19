/**

* Module d'affichage hexadécimal des données brutes
 */

#include <stdio.h>
#include <ctype.h>
#include "hexdump.h"

/* Nombre d'octets par ligne dans l'affichage hexdump */
#define BYTES_PER_LINE 16

/**
* Affiche un hexdump des données brutes
 * 
 * @param data   Pointeur vers les données à afficher
 * @param length Nombre d'octets à afficher
 */
void print_hexdump(const unsigned char *data, int length) {
    for (int offset = 0; offset < length; offset += BYTES_PER_LINE) {
        /* Affichage de l'offset en hexadécimal */
        printf("  %04x  ", offset);
        
        /* Affichage des octets en hexadécimal */
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            if (offset + i < length) {
                printf("%02x ", data[offset + i]);
            } else {
                /* Padding avec espaces pour les lignes incomplètes */
                printf("   ");
            }
            /* Séparateur visuel au milieu de la ligne */
            if (i == 7) {
                printf(" ");
            }
        }
        
        /* Séparateur avant la représentation ASCII */
        printf(" |");
        
        /* Représentation ASCII des caractères */
        for (int i = 0; i < BYTES_PER_LINE && offset + i < length; i++) {
            unsigned char c = data[offset + i];
            /* Caractère imprimable -> lui-même, sinon ->s  '.' */
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("|\n");
    }
}

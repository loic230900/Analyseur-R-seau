/**

Module d'affichage hexadécimal des données brutes
 * 
 * Ce module fournit une fonction d'affichage des données binaires
 * au format hexdump, similaire à la vue "raw" de Wireshark.
 * 
 * Format de sortie :
 * - Colonne 1 : Offset en hexadécimal (4 chiffres)
 * - Colonne 2 : 16 octets en hexadécimal (avec séparateur au milieu)
 * - Colonne 3 : Représentation ASCII (caractères non imprimables → '.')
 * 
 * Exemple :
 *   0000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
 *   0010  0a 43 6f 6e 74 65 6e 74  2d 4c 65 6e 67 74 68 3a  |.Content-Length:|
 * 
 * Cette fonction est utilisée en verbosité 3 pour afficher les données
 * restantes non parsées à la fin de chaque paquet (max 256 octets).
 * 
 */

#include <stdio.h>
#include <ctype.h>
#include "hexdump.h"

/* Nombre d'octets par ligne dans l'affichage hexdump */
#define BYTES_PER_LINE 16

/**
Affiche un hexdump des données brutes
 * 
 * Cette fonction génère une représentation hexadécimale des données
 * passées en paramètre, similaire à l'utilitaire 'xxd' ou la vue
 * "raw" de Wireshark.
 * 
 * Caractéristiques de l'affichage :
 * - 16 octets par ligne
 * - Offset affiché en hexadécimal sur 4 chiffres
 * - Séparateur visuel au milieu de la ligne (après 8 octets)
 * - Représentation ASCII avec '.' pour les caractères non imprimables
 * - Délimiteurs '|' autour de la partie ASCII
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
            /* Caractère imprimable → lui-même, sinon → '.' */
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("|\n");
    }
}

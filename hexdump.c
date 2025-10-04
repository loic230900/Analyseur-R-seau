#include <stdio.h>
#include <ctype.h>
#include "hexdump.h"

void print_hexdump(const unsigned char *data, int length) {
    const int bytes_per_line = 16;
    for (int i = 0; i < length; ++i) {
        printf("%02x ", data[i]);            // affiche l'octet courant en hexadécimal sur 2 digits
        if ((i + 1) % bytes_per_line == 0) {
            printf("\n");                    // retour à la ligne tous les 16 octets
        }
    }
    if (length % bytes_per_line != 0) {
        printf("\n");                        // retour à la ligne final si la dernière ligne est incomplète
    }
}

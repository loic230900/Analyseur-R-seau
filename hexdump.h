#ifndef HEXDUMP_H
#define HEXDUMP_H

/**
 * Impresion d'un hexdump des données fournies.
 * @param data Pointeur vers les données à afficher.
 * @param length Longueur des données en octets.
 * @return void
 */
void print_hexdump(const unsigned char *data, int length);

#endif

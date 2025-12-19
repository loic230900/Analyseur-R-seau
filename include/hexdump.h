/**
 * Ce fichier déclare la fonction print_hexdump() qui affiche les données
 * brutes au format hexadécimal (+ représentation ASCII.)
 * 
 * Utilisé en verbosité 3 pour afficher les données restantes non parsées
 * à la fin de chaque paquet (limité à MAX_HEXDUMP_BYTES = 256 octets).
 */

#ifndef HEXDUMP_H
#define HEXDUMP_H

/**
 * Génère un affichage au format classique hexdump :
 * - Offset en hexadécimal (4 chiffres)
 * - 16 octets par ligne en hexadécimal
 * - Représentation ASCII (non-imprimables = '.')
 * 
 * Exemple de sortie :
 *   0000  48 45 4c 4c 4f 20 57 4f  52 4c 44 0a 00 00 00 00  |HELLO WORLD.....|
 * 
 * @param data   Pointeur vers les données à afficher
 * @param length Nombre d'octets à afficher
 */
void print_hexdump(const unsigned char *data, int length);

#endif /* HEXDUMP_H */

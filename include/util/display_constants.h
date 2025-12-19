/**
 * Ce fichier centralise toutes les constantes numériques utilisées
 * pour contrôler l'affichage des données et éviter les débordements.
 * 
 *
 */

#ifndef DISPLAY_CONSTANTS_H
#define DISPLAY_CONSTANTS_H


/** Nombre maximum d'octets affichés en hexdump (verbosité 3) */
#define MAX_HEXDUMP_BYTES 256

/** Nombre d'octets par ligne dans l'affichage hexdump */
#define HEXDUMP_BYTES_PER_LINE 16

/** Taille maximale du corps HTTP/SMTP/etc. à afficher */
#define MAX_BODY_DISPLAY 2048

/** Recherche arrière pour fin naturelle JSON/XML (en octets) */
#define NATURAL_END_SEARCH_BACK 200

/** Recherche avant pour fin naturelle JSON/XML (en octets) */
#define NATURAL_END_SEARCH_FORWARD 500

/** Seuil de sécurité avant troncature du résumé  */
#define RESUME_SAFE_THRESHOLD 240

/** Taille du buffer pour les lignes de protocoles texte  */
#define LINE_BUFFER_SIZE 512

/** Taille du buffer pour les adresses IP en format texte (IPv4 ou IPv6) */
#define IP_STRING_BUFFER 64

/** Taille du buffer pour les adresses MAC */
#define MAC_STRING_BUFFER 18

#endif /* DISPLAY_CONSTANTS_H */

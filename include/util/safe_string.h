/**
 * Ce fichier fournit des fonctions inline pour la manipulation sécurisée
 * des chaînes de caractères, avec vérification automatique des limites
 * pour éviter les débordements de buffer.
 * 
 * Ces fonctions sont essentielles pour la construction du buffer de résumé
 * en verbosité 1, où de nombreuses concaténations successives sont effectuées.
 * 
 * fonctions static inline c'est pour ça qu'on inclut le code dans le header
 */

#ifndef SAFE_STRING_H
#define SAFE_STRING_H

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/** Taille standard du buffer de résumé (verbosité 1) */
#define RESUME_BUFFER_SIZE 256

/** Marge de sécurité pour éviter les troncatures inattendues */
#define RESUME_SAFETY_MARGIN 16

/**
 * Cette fonction ajoute la chaîne source à la fin de la chaîne destination
 * en vérifiant que le résultat ne dépasse pas la taille du buffer.
 * En cas de dépassement, la chaîne est tronquée proprement.
 * 
 * @param dest      Buffer de destination (doit être initialisé avec une chaîne valide)
 * @param src       Chaîne source à ajouter
 * @param dest_size Taille totale du buffer de destination (incluant le '\0')
 * 
 * @return 1 si ajout complet réussi, 0 si buffer plein ou chaîne tronquée
 */
static inline int safe_strcat(char *dest, const char *src, size_t dest_size) {
    size_t current_len = strlen(dest);
    size_t src_len = strlen(src);
    size_t available = dest_size - current_len - 1;  // -1 pour le '\0' 
    
    if (available == 0) {
        return 0;  // Buffer déjà plein 
    }
    
    if (src_len <= available) {
        // Assez d'espace pour tout ajouter 
        memcpy(dest + current_len, src, src_len + 1);  // +1 pour le '\0'
        return 1;
    } else {
        // Tronquer pour rentrer dans l'espace disponible 
        memcpy(dest + current_len, src, available);
        dest[current_len + available] = '\0';
        return 0;  //Indique que la chaîne a été tronquée 
    }
}

/**
 * 
 * Cette fonction ajoute une chaîne formatée à la fin de la chaîne destination
 * en vérifiant que le résultat ne dépasse pas la taille du buffer.
 * Elle derive de snprintf pour gérer les arguments variables.
 * 
 * @param dest      Buffer de destination
 * @param dest_size Taille totale du buffer
 * @param format    Chaîne de format (syntaxe printf)
 * @param ...       Arguments variables pour le formatage
 * 
 * @return 1 si formatage complet réussi, 0 si buffer plein ou tronqué
 */
static inline int safe_strcat_printf(char *dest, size_t dest_size, const char *format, ...) {
    size_t current_len = strlen(dest);
    size_t available = dest_size - current_len - 1; 
    
    if (available == 0) {
        return 0;
    }
    
    va_list args; // va_list est un type pour gérer les arguments variables trouve grace a l'IA
    va_start(args, format);
    int written = vsnprintf(dest + current_len, available + 1, format, args); // on utilise vsnprintf pour ecrire dans le buffer
    va_end(args);
    
    return (written >= 0 && (size_t)written <= available) ? 1 : 0;
}

/**
 * Cette fonction teste si l'ajout de la chaîne source au buffer destination
 * laisserait encore une marge de sécurité (RESUME_SAFETY_MARGIN octets).
 * 
 * Utilisation typique (ex pour DNS):
 *   if (can_append(resume, " | DNS", RESUME_BUFFER_SIZE)) {
 *       safe_strcat(resume, " | DNS", RESUME_BUFFER_SIZE);
 *   }
 * 
 * @param dest      Buffer de destination
 * @param src       Chaîne à potentiellement ajouter
 * @param dest_size Taille totale du buffer
 * 
 * @return 1 si ajout possible avec marge, 0 sinon
 */
static inline int can_append(const char *dest, const char *src, size_t dest_size) {
    size_t current_len = strlen(dest);
    size_t src_len = strlen(src);
    return (current_len + src_len + RESUME_SAFETY_MARGIN) < dest_size;
}

#endif /* SAFE_STRING_H */

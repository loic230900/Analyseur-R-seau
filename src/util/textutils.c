/**
 * @file textutils.c
 * @brief Utilitaires pour le parsing des protocoles textuels
 * 
 * Ce module fournit des fonctions d'aide pour l'analyse des protocoles
 * de la couche application basés sur du texte (HTTP, SMTP, FTP, IMAP,
 * POP3, Telnet).
 * 
 * Fonctionnalités :
 * - Gestion de l'indentation pour l'affichage hiérarchique
 * - Recherche de fins de ligne (CRLF ou LF)
 * - Extraction de lignes de texte sans les terminaisons
 * - Détection de contenu textuel vs binaire/chiffré
 * 
 * Conventions RFC :
 * - La plupart des protocoles textuels utilisent CRLF (\r\n) comme
 *   terminaison de ligne (RFC 5321 pour SMTP, RFC 2616 pour HTTP, etc.)
 * - Le module accepte aussi LF seul (\n) pour la compatibilité
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "textutils.h"
#include <ctype.h>
#include <stdio.h>

/* ============================================================================
 * FONCTIONS D'AFFICHAGE
 * ============================================================================ */

/**
 * @brief Affiche l'indentation pour la sortie formatée
 * 
 * Cette fonction génère le nombre d'espaces correspondant au niveau
 * d'indentation demandé. Utilisée pour l'affichage hiérarchique des
 * protocoles encapsulés (verbosités 2 et 3).
 * 
 * @param indent Nombre d'espaces à afficher (0 = pas d'indentation)
 */
void print_indent(int indent) {
    for(int i = 0; i < indent; i++) {
        printf(" ");
    }
}

/* ============================================================================
 * FONCTIONS DE PARSING DE TEXTE
 * ============================================================================ */

/**
 * @brief Trouve la position de la fin de ligne dans les données
 * 
 * Recherche la première occurrence d'une terminaison de ligne à partir
 * de l'offset spécifié. Vérifie d'abord CRLF (standard RFC) puis LF seul
 * (compatibilité Unix).
 * 
 * @param data    Pointeur vers les données à analyser
 * @param offset  Position de départ de la recherche
 * @param max_len Longueur maximale des données
 * 
 * @return Position du premier caractère de la terminaison (\r ou \n),
 *         ou -1 si aucune fin de ligne trouvée
 */
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

/**
 * @brief Extrait une ligne de texte sans les terminaisons
 * 
 * Cette fonction copie une ligne complète du buffer source vers
 * le buffer de destination, en excluant les caractères de terminaison
 * (\r\n ou \n).
 * 
 * Comportement :
 * - Cherche la fin de ligne à partir de l'offset
 * - Copie les caractères jusqu'à la fin de ligne
 * - Ajoute un terminateur nul
 * - Retourne la position après la terminaison pour la prochaine ligne
 * 
 * @param data    Pointeur vers les données source
 * @param offset  Position de départ de la ligne
 * @param max_len Longueur maximale des données
 * @param out     Buffer de destination pour la ligne extraite
 * @param out_len Taille du buffer de destination
 * 
 * @return Offset de la prochaine ligne, ou -1 si pas de fin de ligne
 */
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

/* ============================================================================
 * FONCTIONS DE DÉTECTION
 * ============================================================================ */

/**
 * @brief Vérifie si un bloc de données est du texte imprimable
 * 
 * Cette fonction analyse les premiers octets d'un bloc pour déterminer
 * s'il s'agit de texte lisible (protocoles textuels) ou de données
 * binaires/chiffrées.
 * 
 * Algorithme :
 * - Analyse au maximum les 128 premiers octets
 * - Compte les caractères imprimables (isprint) et espaces blancs
 * - Retourne faux immédiatement si un caractère de contrôle suspect est trouvé
 * - Retourne vrai si plus de 80% des caractères sont imprimables
 * 
 * Cas d'utilisation :
 * - Distinguer HTTP en clair de HTTPS chiffré
 * - Détecter les segments STARTTLS après négociation
 * - Identifier les transferts FTP binaires vs texte
 * 
 * @param data Pointeur vers les données à analyser
 * @param len  Longueur des données disponibles
 * 
 * @return 1 si texte imprimable (>80%), 0 sinon
 */
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

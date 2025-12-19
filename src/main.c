/**
 * Ce fichier contient la fonction main() qui :
 * - Parse les arguments de la ligne de commande (-i, -o, -f, -v)
 * - Initialise la session de capture pcap (live ou fichier)
 * - Applique les filtres BPF si spécifiés
 * - Lance la boucle de capture avec pcap_loop()
 * - Gère l'arrêt propre via Ctrl+C (SIGINT)
 * - Affiche les statistiques de capture à la fin
 * 
 * Usage : ./analyseur [-i interface | -o fichier] [-f filtre] [-v 1-3]
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "capture.h"
#include "dns.h"
#include "filter.h"

// Constantes de configuration
#define SNAPLEN_DEFAULT 65535  // Longueur max de capture (évite troncature des gros paquets)
#define PCAP_TIMEOUT_MS 1000   // Timeout de lecture pcap en millisecondes
#define FILTER_BUF_SIZE 256    // Taille du buffer pour stocker le filtre BPF appliqué

// Variables globales pour le gestionnaire de signaux
// (globales car le handler de signal ne peut pas recevoir de paramètres)
static pcap_t *g_handle = NULL;              // Poignée pcap pour pcap_breakloop()
static volatile sig_atomic_t g_stop_capture = 0;  // Drapeau d'arrêt (volatile pour threads)

/**
 * Gestionnaire de signal pour Ctrl+C (SIGINT)
 * Utilise pcap_breakloop() pour interrompre proprement la boucle de capture.
 * 
 * @param sig Numéro du signal reçu (non utilisé, toujours SIGINT)
 */
static void signal_handler(int sig) {
    (void)sig;  // Paramètre non utilisé
    g_stop_capture = 1;
    if(g_handle) {
        pcap_breakloop(g_handle);
    }
}

/**
 * Point d'entrée du programme
 * 
 * Codes de retour :
 * - 0 : Succès (capture terminée normalement ou Ctrl+C)
 * - 1 : Erreur d'arguments (usage incorrect)
 * - 2 : Erreur pcap (interface/fichier inaccessible, filtre invalide)
 * 
 * @param argc Nombre d'arguments
 * @param argv Tableau des arguments
 * @return Code de retour (0=succès, 1=erreur args, 2=erreur pcap)
 */
int main(int argc, char *argv[]) {
    // Variables pour les options de la ligne de commande
    char *interface = NULL;     // Nom de l'interface réseau (-i)
    char *filename = NULL;      // Nom du fichier pcap (-o)
    char *filter_exp = NULL;    // Expression de filtre BPF (-f)
    int opt;                    // Option courante de getopt
    int verbosity = 3;          // Niveau de verbosité par défaut : complet
    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer d'erreur pcap
    pcap_t *handle;             // Poignée de session pcap

    // Analyse des options de la ligne de commande
    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;   // Nom de l'interface pour capture live
                break;
            case 'o':
                filename = optarg;    // Nom du fichier .pcap pour capture hors ligne
                break;
            case 'f':
                filter_exp = optarg;  // Expression de filtre BPF ou alias
                break;
            case 'v':
                verbosity = atoi(optarg); 
                if(verbosity < 1 || verbosity > 3){
                    fprintf(stderr, "Error: Invalid verbosity level (must be between 1 and 3).\n");
                    return 1;
                }
                break;
            default:
                // Affichage de l'aide détaillée
                fprintf(stderr, "Usage: %s [-i interface | -o file] [-f filter] [-v verbosity]\n\n", argv[0]);
                fprintf(stderr, "Options obligatoires (une seule) :\n");
                fprintf(stderr, "  -i <interface>  Capture en temps réel sur une interface réseau (ex: eth0, wlan0)\n");
                fprintf(stderr, "  -o <fichier>    Analyse hors ligne d'un fichier pcap (créé par tcpdump)\n\n");
                fprintf(stderr, "Options facultatives :\n");
                fprintf(stderr, "  -f <filtre>     Filtre BPF ou alias (défaut: aucun - capture tout)\n");
                fprintf(stderr, "  -v <niveau>     Niveau de verbosité: 1=concis, 2=synthétique, 3=complet (défaut: 3)\n\n");
                fprintf(stderr, "Alias de filtres disponibles :\n");
                fprintf(stderr, "  dns             Tout le trafic DNS (UDP et TCP port 53)\n");
                fprintf(stderr, "  web             Trafic HTTP et HTTPS (ports 80, 443)\n");
                fprintf(stderr, "  mail            Tous les protocoles mail (SMTP, IMAP, POP3 et variantes SSL)\n");
                fprintf(stderr, "  smtp, ftp, telnet  Protocoles spécifiques\n\n");
                fprintf(stderr, "Exemples :\n");
                fprintf(stderr, "  %s -i eth0 -v 2 -f dns              # Capture DNS en temps réel, verbosité moyenne\n", argv[0]);
                fprintf(stderr, "  %s -o capture.pcap -v 3             # Analyse complète d'un fichier\n", argv[0]);
                fprintf(stderr, "  %s -i wlan0 -f \"tcp port 80\"        # Filtre BPF personnalisé\n\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Validation des arguments : interface XOR fichier obligatoire
    if ((interface && filename) || (!interface && !filename)) {
        fprintf(stderr, "Error: You must specify either -i (interface) or -o (file), but not both.\n");
        fprintf(stderr, "Use '%s' without arguments to see the full help.\n", argv[0]);
        return 1;
    }

    // Ouverture de la session pcap (live ou offline)
    if(interface) {
        // Mode live: capture en temps réel sur l'interface réseau
        handle = pcap_open_live(interface, SNAPLEN_DEFAULT, 1, PCAP_TIMEOUT_MS, errbuf);
        if(handle == NULL) {
            fprintf(stderr, "Error: Unable to open interface %s: %s\n", interface, errbuf);
            return 2;
        }
    } else {
        // Mode hors ligne : lecture d'un fichier pcap
        handle = pcap_open_offline(filename, errbuf);
        if(handle == NULL) {
            fprintf(stderr, "Error: Unable to open file %s: %s\n", filename, errbuf);
            return 2;
        }
    }

    // Configuration du gestionnaire de signal pour Ctrl+C
    g_handle = handle;
    signal(SIGINT, signal_handler);
    
    // Application du filtre BPF si spécifié
    if (filter_exp) {
        char applied[FILTER_BUF_SIZE];
        int fres = filter_apply(handle, interface, filter_exp, applied, sizeof(applied));
        if (fres != FILTER_OK) {
            pcap_close(handle);
            return 2;
        }
        fprintf(stderr, "BPF filter applied: %s\n", applied);
    }

    // Boucle principale de capture
    // pcap_loop() appelle packet_handler() pour chaque paquet reçu
    capture_args_t args;
    args.verbosity = verbosity;

    int loop_ret = pcap_loop(handle, -1, packet_handler, (u_char *)&args);
    
    // Affichage des statistiques de capture
    if(g_stop_capture || loop_ret == -2) {
        struct pcap_stat stats;
        fprintf(stderr, "\n\n=== Capture Statistics ===\n");
        if(pcap_stats(handle, &stats) == 0) {
            fprintf(stderr, "Packets received by libpcap: %u\n", stats.ps_recv);
            fprintf(stderr, "Packets dropped (kernel):    %u\n", stats.ps_drop);
            fprintf(stderr, "Packets dropped (iface):     %u\n", stats.ps_ifdrop);
            if(stats.ps_drop > 0 || stats.ps_ifdrop > 0) {
                fprintf(stderr, "⚠️  WARNING: Packets were dropped!\n");
                fprintf(stderr, "   Tip: Increase buffer size or reduce verbosity\n");
            } else {
                fprintf(stderr, "✓ No packet loss detected\n");
            }
        } else {
            fprintf(stderr, "Unable to retrieve statistics\n");
        }
        fprintf(stderr, "==========================\n");
    }
    
    // Gestion des codes de retour de pcap_loop
    if(loop_ret == -1) {
        fprintf(stderr, "Error during capture: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }
    if(loop_ret == -2) {
        fprintf(stderr, "Capture interrupted (Ctrl+C)\n");
    } else if(loop_ret == 0) {
        fprintf(stderr, "Capture completed normally\n");
    }
    
    // Fermeture propre de la session pcap
    pcap_close(handle);
    
    return 0;
}
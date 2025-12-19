/**
 * Ce fichier contient la fonction main()
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "capture.h"
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
 * Affiche l'aide détaillée du programme
 * @param prog_name Nom du programme (argv[0])
 */
static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s (-i interface | -o file) -v verbosity [-f filter]\n\n", prog_name);
    fprintf(stderr, "Options obligatoires :\n");
    fprintf(stderr, "  -i <interface>  Capture en temps réel sur une interface réseau (ex: eth0, wlan0)\n");
    fprintf(stderr, "  -o <fichier>    Analyse hors ligne d'un fichier pcap (créé par tcpdump)\n");
    fprintf(stderr, "                  (une seule des deux options -i ou -o doit être spécifiée)\n");
    fprintf(stderr, "  -v <niveau>     Niveau de verbosité: 1=concis, 2=synthétique, 3=complet\n\n");
    fprintf(stderr, "Option facultative :\n");
    fprintf(stderr, "  -f <filtre>     Filtre BPF ou alias (défaut: aucun - capture tout)\n");
    fprintf(stderr, "  -h              Affiche cette aide\n\n");
    fprintf(stderr, "Alias de filtres disponibles (pas tout les protocoles en ont un) :\n");
    fprintf(stderr, "  dns             Tout le trafic DNS \n");
    fprintf(stderr, "  web             Trafic HTTP et HTTPS (ports 80, 443)\n");
    fprintf(stderr, "  mail            Tous les protocoles mail (SMTP, IMAP, POP3 et variantes SSL)\n");
    fprintf(stderr, "  smtp, ftp, telnet  Protocoles spécifiques\n\n");
    fprintf(stderr, "Exemples :\n");
    fprintf(stderr, "  %s -i eth0 -v 2 -f dns              # Capture DNS en temps réel, verbosité moyenne\n", prog_name);
    fprintf(stderr, "  %s -o capture.pcap -v 3             # Analyse complète d'un fichier\n", prog_name);
    fprintf(stderr, "  %s -i wlan0 -f \"tcp port 80\"        # Filtre BPF personnalisé\n\n", prog_name);
}


int main(int argc, char *argv[]) {
    // Variables pour les options de la ligne de commande
    char *interface = NULL;     // Nom de l'interface réseau (-i)
    char *filename = NULL;      // Nom du fichier pcap (-o)
    char *filter_exp = NULL;    // Expression de filtre BPF (-f)
    int opt;                    // Option courante de getopt
    int verbosity = -1;         // Niveau de verbosité (obligatoire)
    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer d'erreur pcap
    pcap_t *handle;             // handle pcap

    // Message court si aucun argument
    if (argc == 1) {
        fprintf(stderr, "Error: Missing required arguments.\n");
        fprintf(stderr, "Usage: %s (-i interface | -o file) -v verbosity [-f filter]\n", argv[0]);
        fprintf(stderr, "Use '%s -h' for detailed help.\n", argv[0]);
        return 1;
    }

    // Analyse des options de la ligne de commande
    while ((opt = getopt(argc, argv, "hi:o:f:v:")) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
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
                print_usage(argv[0]);
                return 1;
        }
    }

    // Validation des arguments obligatoires
    if ((interface && filename) || (!interface && !filename)) {
        fprintf(stderr, "Error: You must specify either -i (interface) or -o (file), but not both.\n");
        fprintf(stderr, "Use '%s' without arguments to see the full help.\n", argv[0]);
        return 1;
    }
    if (verbosity == -1) {
        fprintf(stderr, "Error: You must specify verbosity level with -v (1, 2, or 3).\n");
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
        fprintf(stderr, "\n\n=== Capture Statistics (used for debug) ===\n");
        if(pcap_stats(handle, &stats) == 0) {
            fprintf(stderr, "Packets received by libpcap: %u\n", stats.ps_recv);
            fprintf(stderr, "Packets dropped (kernel):    %u\n", stats.ps_drop);
            fprintf(stderr, "Packets dropped (iface):     %u\n", stats.ps_ifdrop);
            if(stats.ps_drop > 0 || stats.ps_ifdrop > 0) {
                fprintf(stderr, " WARNING: Packets were dropped!\n");
                fprintf(stderr, "   Tip: Increase buffer size or reduce verbosity\n");
            } else {
                fprintf(stderr, "No packet loss detected\n");
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
#include <sys/types.h>        
#include <pcap.h>         
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char **argv) {
    /*verification arguments*/
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer pour les messages d'erreur
    
    /*Rechercher s il y a des interfaces reseaux*/
    if(pcap_lookupdev(errbuf ) == NULL) {
        fprintf(stderr, "Pas d'interface trouvée: %s\n", errbuf);
        return 2;
    } else{
        char device = pcap_lookupdev(errbuf); 
    }
    /*Ouverture du fichier pcap*/
    pcap_t *capture = pcap



    
    return 0;
}
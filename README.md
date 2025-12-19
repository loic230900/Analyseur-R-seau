# Analyseur Réseau

Analyseur de paquets réseau en C utilisant libpcap, développé dans le cadre du TP "Services Réseaux" (M1 SIRIS).

## Fonctionnalités

- **Capture live** sur une interface réseau (nécessite `sudo`)
- **Analyse offline** de fichiers `.pcap` créés par tcpdump
- **3 niveaux de verbosité** : concis, synthétique, complet
- **Filtrage BPF** avec alias prédéfinis

### Protocoles supportés

| Couche | Protocoles |
|--------|------------|
| **L2 - Liaison** | Ethernet, ARP, RARP |
| **L3 - Réseau** | IPv4 (options, fragmentation), IPv6 (extensions) |
| **L4 - Transport** | TCP (options), UDP, ICMP, ICMPv6/NDP |
| **L7 - Application** | DNS, DHCP/BOOTP, HTTP, FTP, SMTP, IMAP, POP3, Telnet |

## Prérequis

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# RHEL/Fedora
sudo dnf install libpcap-devel
```

## Compilation

```bash
make          # Compiler
make clean    # Nettoyer
```

## Utilisation

```bash
./analyseur (-i interface | -o fichier) -v niveau [-f filtre]
```
dependant de l'interface lancer avec sudo.

### Options

| Option | Description |
|--------|-------------|
| `-i <interface>` | Capture live (ex: `eth0`, `wlo1`) |
| `-o <fichier>` | Analyse d'un fichier pcap |
| `-v <1\|2\|3>` | Niveau de verbosité |
| `-f <filtre>` | Filtre BPF ou alias |
| `-h` | Aide |

### Niveaux de verbosité

- **`-v 1`** : Une ligne par trame (timestamp, protocole, longueur)
- **`-v 2`** : Une ligne par couche protocolaire
- **`-v 3`** : Tous les champs avec arborescence détaillée



## Auteur
Waltzing Loïc
Projet individuel - M1 SIRIS, Semestre 1

## Licence

Projet académique - Usage éducatif uniquement

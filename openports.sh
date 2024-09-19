#!/bin/bash

# Définition des couleurs
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # Sans couleur

# Vérification si le script est exécuté avec les droits root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}ERREUR: Ce script doit être exécuté avec sudo ou en tant que root.${NC}"
  exit
fi

echo -e "${BLUE}INFO: Analyse des ports ouverts en cours...${NC}"

# Variables pour stocker les résultats
ipv4_loopback_ports=()
ipv4_external_ports=()
ipv6_loopback_ports=()
ipv6_external_ports=()

# Fonction pour analyser les ports avec ss (Socket Statistics)
analyze_ss_ports() {
  echo -e "${BLUE}INFO: Analyse des ports via 'ss'...${NC}"
  output=$(ss -lntu -pH)
  
  if [[ -z "$output" ]]; then
    echo -e "${RED}ERREUR: Impossible de récupérer les informations via 'ss'.${NC}"
  fi

  while IFS= read -r line; do
    address=$(echo "$line" | awk '{print $5}')
    service=$(echo "$line" | awk '{print $1}')
    pid_info=$(echo "$line" | awk '{print $7}')
    
    # Extraire la commande directement sans passer par le PID
    command=$(echo "$pid_info" | cut -d'"' -f2,4,6 | tr "\"" " ")

    # Découper et traiter l'adresse et le port
    port=$(echo "$address" | awk -F':' '{print $2}')
    ip=$(echo "$address" | awk -F':' '{print $1}')

    # Si le port est nul, essayons une autre extraction
    if [[ -z "$port" ]]; then
      port=$(echo "$address" | awk -F':' '{print $4}')
    fi

    # Gestion des adresses IP (IPv6 uniquement)
    if [[ "$ip" =~ ^\[ ]]; then
      ipv6_part=$(echo "$address" | awk -F':' '{print $3}' | cut -d"]" -f1)
      if [[ "$ipv6_part" == "1" ]]; then
        ip="[::1]"
      else
        ip="[::]"
      fi
    fi

    # Afficher les erreurs si des informations sont manquantes
    if [[ -z "$port" || -z "$ip" ]]; then
      echo -e "${RED}ERREUR: Adresse ou port non trouvés pour la ligne: $line${NC}"
    fi

    # Gestion des adresses IPv4
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      if [[ "$ip" =~ ^127\.0\.0\.[0-9]+$ ]]; then
        ipv4_loopback_ports+=("ss: $port ($service) - Commande: $command")
      elif [[ "$ip" == "0.0.0.0" ]]; then
        ipv4_external_ports+=("ss: $port ($service) - Commande: $command")
      fi
    fi

    # Gestion des adresses IPv6
    if [[ "$ip" == "[::1]" ]]; then
      ipv6_loopback_ports+=("ss: $port ($service) - Commande: $command")
    elif [[ "$ip" == "[::]" ]]; then
      ipv6_external_ports+=("ss: $port ($service) - Commande: $command")
    fi
  done <<< "$output"
}

# Fonction pour analyser les ports avec netstat
analyze_netstat_ports() {
  echo -e "${BLUE}INFO: Analyse des ports via 'netstat'...${NC}"
  
  # Regroupement des informations pour netstat
  output=$(netstat -laputen 2>/dev/null)
  
  # Extraire uniquement les local addresses pour chaque groupe
  info_ipv4_local=$(echo "$output" | grep "127.0.0" | awk '$4 ~ /127.0.0/')
  info_ipv4_externe=$(echo "$output" | grep "0.0.0.0" | awk '$4 ~ /0.0.0.0/')
  info_ipv6_local=$(echo "$output" | grep "::1:" | awk '$4 ~ /::1/')
  info_ipv6_externe=$(echo "$output" | grep ":::")

  # Analyser les adresses IPv4 locales
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $2}'|cut -d":" -f2)
    pid_info=$(echo "$line" |awk '{print $8,$9}'|cut -d "/" -f2|cut -d " " -f1|cut -d ":" -f1)
    
    command=$(echo "$pid_info")
    ipv4_loopback_ports+=("netstat: $port ($protocol) - Commande: $command")
  done <<< "$info_ipv4_local"

  # Analyser les adresses IPv4 externes
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $2}')
    pid_info=$(echo "$line" |awk '{print $8,$9}'|cut -d "/" -f2|cut -d " " -f1|cut -d ":" -f1)
    
    command=$(echo "$pid_info")
    ipv4_external_ports+=("netstat: $port ($protocol) - Commande: $command")
  done <<< "$info_ipv4_externe"

  # Analyser les adresses IPv6 locales
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $4}')
    pid_info=$(echo "$line" |awk '{print $8,$9}'|cut -d "/" -f2|cut -d " " -f1|cut -d ":" -f1)
    
    command=$(echo "$pid_info")
    ipv6_loopback_ports+=("netstat: $port ($protocol) - Commande: $command")
  done <<< "$info_ipv6_local"

  # Analyser les adresses IPv6 externes
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $4}')
    pid_info=$(echo "$line" | awk '{print $8,$9}'|cut -d "/" -f2|cut -d " " -f1|cut -d ":" -f1)
    
    command=$(echo "$pid_info")
    ipv6_external_ports+=("netstat: $port ($protocol) - Commande: $command")
  done <<< "$info_ipv6_externe"
}

# Fonction pour analyser les ports avec Docker (si Docker est présent)
analyze_docker_ports() {
  echo -e "${BLUE}INFO: Analyse des ports exposés par Docker...${NC}"
  if command -v docker &> /dev/null; then
    docker_ports=$(docker ps --format "{{.Names}}: {{.Ports}}")
    
    if [[ -z "$docker_ports" ]]; then
      echo -e "${RED}ERREUR: Aucun conteneur Docker trouvé ou aucun port exposé.${NC}"
    fi

    while IFS= read -r line; do
      container_name=$(echo "$line" | awk -F: '{print $1}')
      container_ports=$(echo "$line" | awk -F': ' '{print $2}')
      
      # Extraire les ports et les adresses IP associées
      echo "$container_ports" | tr ',' '\n' | while IFS= read -r port_mapping; do
        ip=$(echo "$port_mapping" | grep -oE "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|::|localhost)")
        port=$(echo "$port_mapping" | grep -oE "[0-9]+")

        if [[ -z "$ip" || -z "$port" ]]; then
          echo -e "${RED}ERREUR: IP ou port non trouvés pour le conteneur: $container_name${NC}"
        fi
        
        # Gestion des adresses Docker IPv4 et IPv6
        if [[ "$ip" == "127.0.0.1" || "$ip" == "localhost" ]]; then
          ipv4_loopback_ports+=("Docker: $container_name - Port: $port_mapping")
        elif [[ "$ip" == "0.0.0.0" || "$ip" == "::" ]]; then
          ipv4_external_ports+=("Docker: $container_name - Port: $port_mapping")
        elif [[ "$ip" == "[::1]" ]]; then
          ipv6_loopback_ports+=("Docker: $container_name - Port: $port_mapping")
        elif [[ "$ip" == "[::]" ]]; then
          ipv6_external_ports+=("Docker: $container_name - Port: $port_mapping")
        fi
      done
    done <<< "$docker_ports"
  else
    echo -e "${RED}ERREUR: Docker n'est pas installé ou n'est pas accessible.${NC}"
  fi
}

# Analyser les ports via ss (Socket Statistics)
analyze_ss_ports

# Analyser les ports via netstat
analyze_netstat_ports

# Analyser les ports Docker (si applicable)
analyze_docker_ports

# Fonction d'affichage en tableau
display_table() {
  local -n ports_array=$1
  local title=$2
  local fixed_ip=$3  # IP fixe en fonction de la catégorie

  echo -e "${BLUE}==== $title ====${NC}"

  # En-tête du tableau
  printf "%-10s %-10s %-30s %-20s\n" "PORT" "PROTOCOL" "COMMAND" "IP"
  echo "-----------------------------------------------------------------------"

  # Affichage des résultats du tableau
  for entry in "${ports_array[@]}"; do
    # Séparer chaque entrée par ":"
    port=$(echo "$entry" | awk -F ' ' '{print $2}')  # Extrait le port
    protocol=$(echo "$entry" | awk -F ' ' '{print $3}')  # Extrait le protocole
    command=$(echo "$entry" | awk -F'Commande: ' '{print $2}')  # Extrait la commande après 'Commande:'

    # Si des champs sont manquants, on les remplit par "-"
    port=${port:-"-"}
    protocol=${protocol:-"-"}
    command=${command:-"-"}
    ip=${fixed_ip}  # IP fixe passée à la fonction

    # Imprimer chaque ligne avec les colonnes formatées
    printf "%-10s %-10s %-30s %-20s\n" "$port" "$protocol" "$command" "$ip"
  done
  
  echo ""  # Ligne vide pour la lisibilité
}

# Appel de la fonction d'affichage avec l'IP hardcodée
display_table ipv4_loopback_ports "Ports ouverts IPv4 sur 127.0.0.1 (Loopback)" "127.0.0.1"
display_table ipv4_external_ports "Ports ouverts IPv4 sur 0.0.0.0 (Externe)" "0.0.0.0"
display_table ipv6_loopback_ports "Ports ouverts IPv6 sur ::1 (Loopback)" "::1"
display_table ipv6_external_ports "Ports ouverts IPv6 sur [::] (Externe)" "[::]"

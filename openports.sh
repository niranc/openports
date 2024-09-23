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
      # If port is still null, try another extraction
      if [[ -z "$port" || "$port" == "127.0.0.1]" ]]; then
        port=$(echo "$address" | awk -F':' '{print $5}')
      fi
    fi
    # Gestion des adresses IP (IPv6 uniquement)
    # Gestion du cas où l'IP est "*"
    if [[ "$ip" == "*" ]]; then
        ip="0.0.0.0"
    fi

    if [[ "$ip" =~ ^\[ ]]; then
      ipv6_part=$(echo "$address" | awk -F':' '{print $1":"$2":"$3":"$4}')
      if [[ "$ipv6_part" == "[::ffff:127.0.0.1]" ]]; then
        ip="[::1]"
      elif [[ "$ipv6_part" == "[::ffff:0.0.0.0]" ]]; then
        ip="[::]"
      fi
      ipv6_part=$(echo "$address" | awk -F':' '{print $3}' | cut -d"]" -f1)
      if [[ "$ipv6_part" == "1" ]]; then
        ip="[::1]"
      else
        ip="[::]"
      fi
    fi

    echo "Port: $port, IP: $ip, Service: $service, Command: $command"

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
  info_ipv6_externe=$(echo "$output" | grep ":::" | awk '$4 ~ /:::/' )

  # Analyser les adresses IPv4 locales
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $2}'|cut -d":" -f2)
    # Calculer le nombre de champs dans la ligne
    number=$(echo "$line" | awk '{print NF}')
    
    # Déterminer le pid_info en fonction du nombre de champs
    if [ "$number" -eq 8 ]; then
      pid_info=$(echo "$line" | awk '{print $8}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    elif [ "$number" -eq 9 ]; then
      pid_info=$(echo "$line" | awk '{print $9}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    else
      pid_info="Unknown"
    fi
    
    command=$(echo "$pid_info")
    ipv4_loopback_ports+=("netstat: $port ($protocol) - Commande: $command")
    echo "Port: $port, IP: $ip, Service: $service, Command: $command"
  done <<< "$info_ipv4_local"

  # Analyser les adresses IPv4 externes
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $2}')
    number=$(echo "$line" | awk '{print NF}')
    
    # Déterminer le pid_info en fonction du nombre de champs
    if [ "$number" -eq 8 ]; then
      pid_info=$(echo "$line" | awk '{print $8}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    elif [ "$number" -eq 9 ]; then
      pid_info=$(echo "$line" | awk '{print $9}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    else
      pid_info="Unknown"
    fi    
    command=$(echo "$pid_info")
    ipv4_external_ports+=("netstat: $port ($protocol) - Commande: $command")
    echo "Port: $port, IP: $ip, Service: $service, Command: $command"
  done <<< "$info_ipv4_externe"

  # Analyser les adresses IPv6 locales
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $4}')
    number=$(echo "$line" | awk '{print NF}')
    
    # Déterminer le pid_info en fonction du nombre de champs
    if [ "$number" -eq 8 ]; then
      pid_info=$(echo "$line" | awk '{print $8}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    elif [ "$number" -eq 9 ]; then
      pid_info=$(echo "$line" | awk '{print $9}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    else
      pid_info="Unknown"
    fi    
    command=$(echo "$pid_info")
    ipv6_loopback_ports+=("netstat: $port ($protocol) - Commande: $command")
    echo "Port: $port, IP: $ip, Service: $service, Command: $command"
  done <<< "$info_ipv6_local"

  # Analyser les adresses IPv6 externes
  while IFS= read -r line; do
    protocol=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $4}' | awk -F':' '{print $4}')
    number=$(echo "$line" | awk '{print NF}')
    
    # Déterminer le pid_info en fonction du nombre de champs
    if [ "$number" -eq 8 ]; then
      pid_info=$(echo "$line" | awk '{print $8}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    elif [ "$number" -eq 9 ]; then
      pid_info=$(echo "$line" | awk '{print $9}' | cut -d "/" -f2 | cut -d " " -f1 | cut -d ":" -f1)
    else
      pid_info="Unknown"
    fi    
    command=$(echo "$pid_info")
    ipv6_external_ports+=("netstat: $port ($protocol) - Commande: $command")
    echo "Port: $port, IP: $ip, Service: $service, Command: $command"
  done <<< "$info_ipv6_externe"
}

# Fonction pour analyser les ports avec Docker (si Docker est présent)
analyze_docker_ports() {
  echo -e "${BLUE}INFO: Analyse des ports exposés par Docker...${NC}"
  if command -v docker &> /dev/null; then
    container_ids=$(docker ps -q)
    
    if [[ -z "$container_ids" ]]; then
      echo -e "${RED}ERREUR: Aucun conteneur Docker trouvé.${NC}"
      return
    fi

    for container_id in $container_ids; do
      container_name=$(docker inspect --format '{{.Name}}' "$container_id" | sed 's/\///')
      port_mappings=$(docker port "$container_id")
      
      if [[ -z "$port_mappings" ]]; then
        echo -e "${YELLOW}AVERTISSEMENT: Aucun port exposé pour le conteneur $container_name.${NC}"
        continue
      fi

      #echo -e "${GREEN}Ports exposés pour le conteneur $container_name:${NC}"

      while IFS= read -r mapping; do
        container_port=$(echo "$mapping" | awk '{print $1}' | cut -d'/' -f1)
        protocol=$(echo "$mapping" | awk '{print $1}' | cut -d'/' -f2)
        host_binding=$(echo "$mapping" | awk '{print $3}')
        
        ip=$(echo "$host_binding" | cut -d':' -f1)
        if [[ "$ip" == "[" ]]; then
          ip=$(echo "$host_binding" | cut -d':' -f1,2,3)
        fi

        port=$(echo "$host_binding" | cut -d':' -f2)
        if [[ -z "$port" ]]; then
          port=$(echo "$host_binding" | cut -d':' -f4)
        fi

        #echo -e "  ${CYAN}$ip:$port -> $container_port/$protocol${NC}"

        if [[ "$ip" == "0.0.0.0" ]]; then
          ipv4_external_ports+=("Docker: $port ($protocol) - Commande: $container_name")
        elif [[ "$ip" == "127.0.0.1" ]]; then
          ipv4_loopback_ports+=("Docker: $port ($protocol) - Commande: $container_name")
        elif [[ "$ip" == "[::]" ]]; then
          ipv6_external_ports+=("Docker: $port ($protocol) - Commande: $container_name")
        elif [[ "$ip" == "[::1]" ]]; then
          ipv6_loopback_ports+=("Docker: $port ($protocol) - Commande: $container_name")
        else
          echo -e "${YELLOW}AVERTISSEMENT: Adresse IP non reconnue pour le conteneur $container_name: $ip${NC}"
        fi
      done <<< "$port_mappings"
      echo ""
    done
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

  # Parcourir tous les ports possibles
  # Créer un tableau associatif pour indexer les ports
  declare -A port_index

  # Indexer les ports
  for entry in "${ports_array[@]}"; do
    current_port=$(echo "$entry" | awk '{print $2}')
    protocol=$(echo "$entry" | awk -F'[()]' '{print $2}')
    command=$(echo "$entry" | awk -F'Commande: ' '{print $2}')
    
    # Si des champs sont manquants, on les remplit par "-"
    protocol=${protocol:-"-"}
    command=${command:-"-"}
    
    port_index[$current_port]="$protocol|$command"
  done

  # Trier les ports et afficher les résultats
  for port in $(echo "${!port_index[@]}" | tr ' ' '\n' | sort -n); do
    IFS='|' read -r protocol command <<< "${port_index[$port]}"
    printf "%-10s %-10s %-30s %-20s\n" "$port" "$protocol" "$command" "$fixed_ip"
  done
  
  echo ""  # Ligne vide pour la lisibilité
}

# Appel de la fonction d'affichage avec l'IP hardcodée
display_table ipv4_loopback_ports "Ports ouverts IPv4 sur 127.0.0.1 (Loopback)" "127.0.0.1"
display_table ipv4_external_ports "Ports ouverts IPv4 sur 0.0.0.0 (Externe)" "0.0.0.0"
display_table ipv6_loopback_ports "Ports ouverts IPv6 sur ::1 (Loopback)" "::1"
display_table ipv6_external_ports "Ports ouverts IPv6 sur [::] (Externe)" "[::]"

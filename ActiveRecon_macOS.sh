#!/bin/bash

# Colours
red=$'\e[31m'
green=$'\e[32m'
yellow=$'\e[33m'
end=$'\e[0m'

# Banner
echo -e "${red}
 _______  _______ __________________          _______  _______  _______  _______  _______  _
(  ___  )(  ____ \\__   __/\__   __/|\     /|(  ____ \(  ____ )(  ____ \(  ____ \(  ___  )( (    /|
| (   ) || (    \/   ) (      ) (   | )   ( || (    \/| (    )|| (    \/| (    \/| (   ) ||  \  ( |
| (___) || |         | |      | |   | |   | || (__    | (____)|| (__    | |      | |   | ||   \ | |
|  ___  || |         | |      | |   ( (   ) )|  __)   |     __)|  __)   | |      | |   | || (\ \) |
| (   ) || |         | |      | |    \ \_/ / | (      | (\ (   | (      | |      | |   | || | \   |
| )   ( || (____/\   | |   ___) (___  \   /  | (____/\| ) \ \__| (____/\| (____/\| (___) || )  \  |
|/     \|(_______/   )_(   \_______/   \_/   (_______/|/   \__/(_______/(_______/(_______)|/    )_)

by: @p0ch4t - <joaquin.pochat@istea.com.ar>
macOS Version

${end}"

# Get script directory (works from current directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR"
TOOLS_DIR="$WORK_DIR/.tools_ActiveRecon"
TARGETS_DIR="$WORK_DIR/Targets"
PROGRAMS_DIR="$WORK_DIR/Programs"

# Environment Variables
bot_token=$(printenv bot_telegram_token) ## Cree una variable de entorno con su bot token de telegram
chat_ID=$(printenv chat_ID) ## Cree una variable de entorno con su chat_ID de telegram
WPSCAN_API_TOKEN=$(printenv WPSCAN_API_TOKEN) ## Cree una variable de entorno con su API-TOKEN de WpScan
date=$(date '+%Y-%m-%d')
cookies='' ## --> Setee sus cookies: Ej: session_id=test123;privelege=admin
authorization_token='' ## --> Setee su Authorization Token. Ej: Bearer ey1231234....
WORD_RESPONSE='' ## --> Setee una palabra. Esto sirve para buscar tokens de sesion en respuestas del servidor (para usar con XSS)

# Detect macOS architecture
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" ]]; then
    MACOS_ARCH="arm64"
else
    MACOS_ARCH="amd64"
fi

# Functions

check_dependencies(){
	echo -e "${green}[+] ${end}Chequeando dependencias...\n"
    mkdir -p "$TOOLS_DIR"
    mkdir -p "$TARGETS_DIR"
    mkdir -p "$PROGRAMS_DIR"
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo -e "${yellow}[!]${end} Homebrew no está instalado. Por favor instálelo desde https://brew.sh"
        echo -e "${yellow}[*]${end} Ejecute: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    # Check and install Go
    if ! command -v go &> /dev/null; then
        echo -e "${yellow}[!]${end} Go no está instalado. Instalando..."
        if brew install go &> /dev/null; then
            echo -e "${green}[V] Go instalado correctamente!${end}"
        else
            echo -e "${red}[X] Error al instalar Go. Por favor instálelo manualmente.${end}"
            exit 1
        fi
    else
        echo -e "${green}[V] Go ya está instalado${end}"
    fi
    
    # Check and install Python3
    if ! command -v python3 &> /dev/null; then
        echo -e "${yellow}[!]${end} Python3 no está instalado. Instalando..."
        if brew install python3 &> /dev/null; then
            echo -e "${green}[V] Python3 instalado correctamente!${end}"
        else
            echo -e "${red}[X] Error al instalar Python3. Por favor instálelo manualmente.${end}"
            exit 1
        fi
    else
        echo -e "${green}[V] Python3 ya está instalado${end}"
    fi
    
    # Add tools directory to PATH for this session
    export PATH="$PATH:$TOOLS_DIR:$HOME/go/bin"
    
	dependencies=(go unzip pip3 docker findomain assetfinder amass subfinder httpx ScanOpenRedirect.py gau waybackurls aquatone nuclei zile.py linkfinder.py unfurl subjs dirsearch subjack chromium)
	for dependency in "${dependencies[@]}"; do
		# Check if dependency is installed
		found=0
		if command -v "$dependency" > /dev/null 2>&1; then
			found=1
		elif [ -f "$TOOLS_DIR/$dependency" ]; then
			found=1
		elif [ "$dependency" == "linkfinder.py" ] && [ -f "$TOOLS_DIR/linkfinder.py" ]; then
			found=1
		elif [ "$dependency" == "ScanOpenRedirect.py" ] && [ -f "$TOOLS_DIR/ScanOpenRedirect.py" ]; then
			found=1
		elif [ "$dependency" == "zile.py" ] && [ -f "$TOOLS_DIR/zile.py" ]; then
			found=1
		fi
		
		if [ "$found" -eq "0" ]; then
			echo -e "${red}[X] $dependency ${end}no esta instalado."
			case $dependency in
                docker)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    brew install --cask docker &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente! Asegúrese de abrir Docker Desktop."
                    ;;
                go)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    brew install go &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
                unzip)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    brew install unzip &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
                pip3)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    brew install python3 &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
                chromium)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    brew install --cask chromium &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
				findomain)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, if not available use direct download
					if brew install findomain &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/download/8.2.1/findomain-osx.zip"
						curl -L -s "$FINDOMAIN_URL" -o "$TOOLS_DIR/findomain.zip" && \
						unzip -qq "$TOOLS_DIR/findomain.zip" -d "$TOOLS_DIR/" 2>/dev/null && \
						rm "$TOOLS_DIR/findomain.zip" 2>/dev/null && \
						chmod +x "$TOOLS_DIR/findomain" && \
						echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
					;;
				assetfinder)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install assetfinder &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/tomnomnom/assetfinder@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
					;;
				amass)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install amass &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/OWASP/Amass/v3/cmd/amass@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
					;;
				subfinder)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install subfinder &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
					;;
				httpx)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install httpx &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/projectdiscovery/httpx/cmd/httpx@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
					;;
                ScanOpenRedirect.py)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    curl -L -s https://raw.githubusercontent.com/p0ch4t/ScanOpenRedirect/main/ScanOpenRedirect.py -o "$TOOLS_DIR/ScanOpenRedirect.py" && \
                    chmod +x "$TOOLS_DIR/ScanOpenRedirect.py" && \
                    # Add shebang if not present
                    if ! head -1 "$TOOLS_DIR/ScanOpenRedirect.py" | grep -q "^#!"; then
                        sed -i '' '1s/^/#!\/usr\/bin\/env python3\n/' "$TOOLS_DIR/ScanOpenRedirect.py"
                    fi && \
                    # Install requests module
                    pip3 install --user requests -q 2>/dev/null || pip3 install --break-system-packages requests -q 2>/dev/null || pip3 install requests -q && \
                    echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
                gau)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install gau &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/lc/gau/v2/cmd/gau@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
					;;
                waybackurls)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install waybackurls &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/tomnomnom/waybackurls@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
                    ;;
				aquatone)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Use correct macOS URL based on architecture
					if [[ "$MACOS_ARCH" == "arm64" ]]; then
						# Check if arm64 version exists, otherwise use universal or amd64
						AQUATONE_URL="https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip"
					else
						AQUATONE_URL="https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip"
					fi
					curl -L -s "$AQUATONE_URL" -o "$TOOLS_DIR/aquatone.zip" && \
					unzip -q "$TOOLS_DIR/aquatone.zip" -d "$TOOLS_DIR" 2>/dev/null && \
					rm "$TOOLS_DIR/aquatone.zip" "$TOOLS_DIR/README.md" "$TOOLS_DIR/LICENSE.txt" 2>/dev/null && \
					chmod +x "$TOOLS_DIR/aquatone" && \
					echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
                nuclei)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    # Try brew first, fallback to go install
                    if brew install nuclei &> /dev/null 2>&1; then
                        echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
                    else
                        go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    fi
                    ;;
				zile.py)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					curl -L -s https://raw.githubusercontent.com/bonino97/new-zile/master/zile.py -o "$TOOLS_DIR/zile.py" && \
					chmod +x "$TOOLS_DIR/zile.py" && \
					if ! head -1 "$TOOLS_DIR/zile.py" | grep -q "^#!"; then
						sed -i '' '1s/^/#!\/usr\/bin\/env python3\n/' "$TOOLS_DIR/zile.py"
					fi && \
					pip3 install --user termcolor requests -q 2>/dev/null || pip3 install --break-system-packages termcolor requests -q 2>/dev/null || pip3 install termcolor requests -q && \
					echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				linkfinder.py)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					if [ -d "$TOOLS_DIR/LinkFinder" ]; then
						rm -rf "$TOOLS_DIR/LinkFinder"
					fi
					git clone -q https://github.com/GerbenJavado/LinkFinder.git "$TOOLS_DIR/LinkFinder" && \
					pip3 install --user -r "$TOOLS_DIR/LinkFinder/requirements.txt" -q 2>/dev/null || pip3 install --break-system-packages -r "$TOOLS_DIR/LinkFinder/requirements.txt" -q 2>/dev/null || pip3 install -r "$TOOLS_DIR/LinkFinder/requirements.txt" -q && \
					ln -sf "$TOOLS_DIR/LinkFinder/linkfinder.py" "$TOOLS_DIR/linkfinder.py" && \
					echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
                unfurl)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install unfurl &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/tomnomnom/unfurl@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
                    ;;
				subjs)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					# Try brew first, fallback to go install
					if brew install subjs &> /dev/null 2>&1; then
						echo -e "${green}[V] $dependency${end} instalado correctamente via brew!"
					else
						go install github.com/lc/subjs@latest &> /dev/null 2>&1 && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					fi
					;;
				dirsearch)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					pip3 install --user dirsearch -q 2>/dev/null || pip3 install --break-system-packages dirsearch -q 2>/dev/null || pip3 install dirsearch -q && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				subjack)
					echo -e "${yellow}[..]${end} Instalando $dependency"
                    go install github.com/haccer/subjack@latest &> /dev/null 2>&1 && \
					mkdir -p "$HOME/.config/subjack" && \
					curl -L -s "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" -o "$HOME/.config/subjack/fingerprints.json" && \
					# Create in multiple expected locations
					mkdir -p "$HOME/go/src/github.com/haccer/subjack" && \
					cp "$HOME/.config/subjack/fingerprints.json" "$HOME/go/src/github.com/haccer/subjack/fingerprints.json" && \
					# Also in /src for older versions
					mkdir -p "/src/github.com/haccer/subjack" 2>/dev/null && \
					cp "$HOME/.config/subjack/fingerprints.json" "/src/github.com/haccer/subjack/fingerprints.json" 2>/dev/null || true && \
					echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
			esac
		else
			echo -e "${green}[V] $dependency${end}"
		fi
	done
	
	# Verify Go bin directory exists and is in PATH
	if [ -d "$HOME/go/bin" ]; then
		export PATH="$PATH:$HOME/go/bin"
	fi
	
	# Ensure tools directory is in PATH
	export PATH="$PATH:$TOOLS_DIR"
}

main(){
    # Validaciones
    if [ ! -f "$TARGETS_DIR/$file" ]; then
        echo -e "${red}\n[X]${end} No se encontró '$file'. Cree un archivo target_{program}.txt con los principales dominios en la ruta $TARGETS_DIR/" && exit 1
    fi
    file="$TARGETS_DIR/$file"
    
    mkdir -p "$PROGRAMS_DIR/$program/Directories/js_endpoints/"
    mkdir -p "$PROGRAMS_DIR/$program/Directories/dirsearch_endpoints/"
    mkdir -p "$PROGRAMS_DIR/$program/Data/Directories"
    mkdir -p "$PROGRAMS_DIR/$program/Images/dominios_crt_sh"
    mkdir -p "$PROGRAMS_DIR/$program/Images/dominios_a_revisar"
    mkdir -p "$PROGRAMS_DIR/$program/Data/Domains"
    mkdir -p "$PROGRAMS_DIR/$program/Images/dominios_vivos"
    
    cd "$PROGRAMS_DIR/$program/Data/Domains"
    get_domains
    get_alive
    get_subdomain_takeover
    get_all_urls
    get_suspects_files
    scan_wordpress_domains
    get_open_redirects
    scan_open_redirect
    get_especial_domains
    if [[ $WORD_RESPONSE ]]; then
        find_token_session_on_response
    fi
    get_paths
    get_js
    get_tokens
    get_endpoints
    new_domains
    get_aquatone
    scan_nuclei
    find "$PROGRAMS_DIR/$program/" -type f -empty -delete
}

get_domains() {
    echo -e "${red}\n[+]${end} Escaneo de dominios..."
    findomain -f "$file" -r -u findomain_domains
    cat "$file" | assetfinder --subs-only | tee -a assetfinder_domains
    amass enum -df "$file" -passive -o ammas_passive_domains
    subfinder -dL "$file" -o subfinder_domains
    sort -u *_domains -o subdomains 2>/dev/null
    cat subdomains | rev | cut -d . -f 1-3 | rev | sort -u | tee root_subdomains
    cat * 2>/dev/null | unfurl domains | sort -u > all_domains
    for domain in $(cat "$file"); do
        cat all_domains | grep "$domain" | unfurl format %s://%d%p | sort -u >> all_domains.txt
    done
    find . -type f -not -name '*.txt' -delete
    number_domains=$(wc -l "$PROGRAMS_DIR/$program/Data/Domains/all_domains.txt" 2>/dev/null | awk '{print $1}')
    echo -e "${green}\n[V] ${end}Escaneo finalizado. Dominios obtenidos: $number_domains"
}

get_alive() {
    echo -e "${red}\n[+]${end} Escaneo de dominios vivos..."

    cat all_domains.txt | httpx -mc 200 -timeout 3 -H "User-Agent: Firefox AppSec" -H "Cookie: $cookies" -H "Authorization: $authorization_token" 2>/dev/null > "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt"
    number_domains=$(wc -l "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt" | awk '{print $1}')

    echo -e "${green}\n[V] ${end}Escaneo finalizado. Dominios vivos: $number_domains"
}

get_subdomain_takeover(){
	echo -e "${red}\n[+]${end} Escaneo en busqueda de subdomains takeovers"
	if [ -f "$PROGRAMS_DIR/$program/Data/Domains/all_domains.txt" ] && [ -s "$PROGRAMS_DIR/$program/Data/Domains/all_domains.txt" ]; then
		# Set SUBJACK_FINGERPRINTS environment variable
		export SUBJACK_FINGERPRINTS="$HOME/.config/subjack/fingerprints.json"
		subjack -w "$PROGRAMS_DIR/$program/Data/Domains/all_domains.txt" -t 100 -timeout 30 -o "$PROGRAMS_DIR/$program/Data/possible_subdomains_takeover.txt" 2>/dev/null || true
	else
		echo -e "${yellow}[!]${end} No se encontró archivo all_domains.txt. Saltando este paso."
	fi
}

get_all_urls() {
    echo -e "${red}\n[+]${end} Escaneo de dominios en Waybackurl, Commoncrawl, Otx y Urlscan. Esto puede demorar bastante..."
    cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt" | gau --threads 100 --timeout 10 --fp --retries 3 > "$PROGRAMS_DIR/$program/Data/Domains/all_urls"
    cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt" | waybackurls >> "$PROGRAMS_DIR/$program/Data/Domains/all_urls"
    for domain in $(cat "$file"); do
        cat all_urls | grep "$domain" | unfurl format %s://%d%p | grep -viE "(png|jpg|jpeg|gif|pdf|mp4|svg|ttf|eot|woff|woff2|css)" | sort -u >> all_urls.txt
    done
    number_domains=$(wc -l "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" | awk '{print $1}')
    rm all_urls 2>/dev/null
    echo -e "${green}\n[V] ${end}URLs obtenidas correctamente. Cantidad de URLs obtenidas: $number_domains"
}

get_suspects_files(){
    echo -e "${red}\n[+]${end} Buscando URLs con files php, aspx, jsp, ruby y perl"
    if [ -f "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" ] && [ -s "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" ]; then
        cat "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" | grep -E "[a-zA-Z0-9_-]+\.(php|aspx|jsp|pl|rb)(\?|$)" | sort -u > dominios_a_analizar 2>/dev/null
        for url in $(cat dominios_a_analizar); do
            dominio_path=$(echo "$url" | unfurl format %d%p)
            cat dominios_a_analizar | grep "$dominio_path" | head -n1 >> "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt"
        done
        sort -u "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt" -o "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt" 2>/dev/null
        rm -f dominios_a_analizar
    else
        echo -e "${yellow}[!]${end} No se encontró archivo all_urls.txt. Saltando este paso."
        touch "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt"
    fi
    echo -e "${green}\n[V] ${end}Escaneo finalizado!"
}

scan_wordpress_domains(){
    echo -e "${red}\n[+]${end} Iniciando reconocimiento y escaneo de sitios Wordpress"
    if [ -f "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt" ]; then
        cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt" | unfurl format %s://%d | httpx -tech-detect 2>/dev/null | grep -i Wordpress | cut -d " " -f1 > revision_domains 2>/dev/null
        cat revision_domains "$PROGRAMS_DIR/$program/Data/Domains/all_domains.txt" 2>/dev/null | sort -u | httpx -tech-detect 2>/dev/null | grep -i Wordpress | cut -d " " -f1 > wordpress_domains.txt 2>/dev/null
    fi
    if [ -f wordpress_domains.txt ] && [ -s wordpress_domains.txt ]; then
        for url in $(cat wordpress_domains.txt); do
        if [[ $WPSCAN_API_TOKEN ]]; then
            docker run -it --rm wpscanteam/wpscan --url "$url" --update --exclude-content-based --force --random-user-agent --api-token "$WPSCAN_API_TOKEN" --enumerate | tee -a wordpress_scan.txt
        else
            docker run -it --rm wpscanteam/wpscan --url "$url" --update --exclude-content-based --force --random-user-agent --enumerate | tee -a wordpress_scan.txt
        fi
        done
    fi
    rm revision_domains 2>/dev/null
    echo -e "${green}\n[V] ${end}Escaneo finalizado!"
}

get_open_redirects() {
    echo -e "${red}\n[+]${end} Buscando URLs susceptibles a Open Redirect"
    if [ -f "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" ] && [ -s "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" ]; then
        cat "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" | sort -u | grep -E "(%253D|%3D|=)http[s]?(%253A|%3A|:)(%252F|%2F|/)(%252F|%2F|/)[A-Za-z0-9-]+\." | httpx -mc 200,301,302 -timeout 3 -H "User-Agent: Firefox AppSec" -H "Cookie: $cookies" -H "Authorization: $authorization_token" 2>/dev/null | tee -a "$PROGRAMS_DIR/$program/Data/possible_open_redirect.txt"
        number_domains=$(wc -l "$PROGRAMS_DIR/$program/Data/possible_open_redirect.txt" 2>/dev/null | awk '{print $1}')
        echo -e "${green}\n[V] ${end}Busqueda finalizada! Dominios obtenidos: $number_domains"
    else
        echo -e "${yellow}[!]${end} No se encontró archivo all_urls.txt. Saltando este paso."
        touch "$PROGRAMS_DIR/$program/Data/possible_open_redirect.txt"
    fi
}

scan_open_redirect(){
    echo -e "${red}\n[+]${end} Comenzando escaneo Open Redirect..."
    "$TOOLS_DIR/ScanOpenRedirect.py" -f "$PROGRAMS_DIR/$program/Data/possible_open_redirect.txt" -c "$cookies"
    mv "$PROGRAMS_DIR/$program/Data/Domains/vulnerable_open_redirect.txt" "$PROGRAMS_DIR/$program/Data/" 2>/dev/null
    mv "$PROGRAMS_DIR/$program/Data/Domains/otros_posibles_dom_open_redirect.txt.txt" "$PROGRAMS_DIR/$program/Data/" 2>/dev/null
    if [[ "$(wc -w "$PROGRAMS_DIR/$program/Data/vulnerable_open_redirect.txt" 2>/dev/null | awk '{print $1}')" > "0" ]]; then
        echo -e "${green}\n[V] ${end}URLs vulnerables encontradas!." && send_alert2
    else
        rm -f "$PROGRAMS_DIR/$program/Data/vulnerable_open_redirect.txt"
    fi
    echo -e "${green}\n[V] ${end}Escaneo finalizado!"
}

find_token_session_on_response(){
    echo -e "${red}\n[+]${end} Buscando '$WORD_RESPONSE' en las respuestas del servidor"
    cat "$PROGRAMS_DIR/$program/Data/Domains/all_urls.txt" | httpx -mc 200 -timeout 3 -ms "$WORD_RESPONSE" -H "User-Agent: Firefox AppSec" -H "Cookie: $cookies" -H "Authorization: $authorization_token" 2>/dev/null > "$PROGRAMS_DIR/$program/Data/tokens_on_response.txt"
    echo -e "${green}\n[V] ${end}Escaneo finalizado!"
}

get_especial_domains(){
    echo -e "${red}\n[+]${end} Busqueda especial de dominios con Crt.sh"
    rm -f "$PROGRAMS_DIR/$program/Data/Domains/dominios_crt_sh.txt"
    organization_names=()
    echo -e "${yellow}\n[*]${end} Certificados:"
    for dominio in $(cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt"); do
        name=$(curl -s 'https://www.digicert.com/api/check-host.php' --data-raw "host=$dominio" | grep -E -oh "Organization = [A-Za-z0-9. ]+" | cut -d "=" -f2 | sed 's/^[[:space:]]//g')
        if [[ ! "${organization_names[*]}" =~ "${name}" ]]; then
            echo "$name - $dominio"
            name=$(echo "$name" | sed 's/\s/\+/g')
            echo "https://crt.sh/?q=$name&dominio_encontrado=$dominio" >> "$PROGRAMS_DIR/$program/Data/Domains/dominios_crt_sh.txt"
            organization_names+="$name"
        fi
    done
    echo -e "${green}\n[V] ${end}Busqueda finalizada! Guardados en: $PROGRAMS_DIR/$program/Data/dominios_crt_sh.txt"
}

get_paths() {
    echo -e "${red}\n[+]${end} Busqueda de directorios con 'dirsearch' de dominios a revisar"
    domains=()
    for url in $(cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt"); do
        domain=$(echo "$url" | unfurl format %d)
        if [[ ! "${domains[*]}" =~ "${domain}" ]]; then
            domains+="$domain "
        fi
    done
    for host in ${domains[@]}; do
        dirsearch_file=$(echo "${host##*/}").txt
        dirsearch -e php,aspx,jsp,pl,rb -t 50 -u "$host" --user-agent="Firefox AppSec" --cookie="$cookies" --header="Authorization: $authorization_token" --format plain -o "$PROGRAMS_DIR/$program/Data/Directories/$dirsearch_file" | grep Target && tput sgr0
    done
    echo -e "${green}\n[V] ${end}Busqueda finalizada!"
}

new_domains(){
    echo -e "${red}\n[+]${end} Buscando diferencias de escaneos anteriores..."
    # Check if there are any previous scan files
    if ls "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos_20"* 1> /dev/null 2>&1; then
        for dominio in $(cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt" | unfurl format %d); do
            found=0
            for old_file in "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos_20"*; do
                if grep -q "^$dominio$" "$old_file" 2>/dev/null || grep -q "://$dominio" "$old_file" 2>/dev/null; then
                    found=1
                    break
                fi
            done
            if [ "$found" -eq "0" ]; then
                echo "$dominio" | tee -a "$PROGRAMS_DIR/$program/Data/Domains/nuevos_dominios_$date.txt"
            fi
        done
        if [ -f "$PROGRAMS_DIR/$program/Data/Domains/nuevos_dominios_$date.txt" ]; then
            echo -e "${green}[V] ${end}Diferencias encontradas!." && send_alert1
        fi
    else
        echo -e "${yellow}[*] ${end}No se encontraron escaneos anteriores. Este es el primer escaneo."
    fi
    mv "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt" "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos_$date.txt" 2>/dev/null
}

get_aquatone() {
    echo -e "${red}\n[+]${end} Sacando capturas de dominios..."
    # Find Chromium path on macOS
    CHROMIUM_PATH=$(which chromium 2>/dev/null || which chromium-browser 2>/dev/null || find /Applications -name "Chromium.app" -type d 2>/dev/null | head -1)
    if [ -z "$CHROMIUM_PATH" ]; then
        CHROMIUM_PATH="/Applications/Chromium.app/Contents/MacOS/Chromium"
    elif [[ "$CHROMIUM_PATH" == *".app"* ]]; then
        CHROMIUM_PATH="$CHROMIUM_PATH/Contents/MacOS/Chromium"
    fi
    
    if [ -f "$CHROMIUM_PATH" ]; then
        cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos_$date.txt" | "$TOOLS_DIR/aquatone" --ports xlarge -out "$PROGRAMS_DIR/$program/Images/dominios_vivos" -chrome-path "$CHROMIUM_PATH" && echo -e "${green}\n[V] ${end}Capturas de dominios_vivos_$date realizadas correctamente."
        cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt" | "$TOOLS_DIR/aquatone" --ports xlarge -out "$PROGRAMS_DIR/$program/Images/dominios_a_revisar" -chrome-path "$CHROMIUM_PATH" && echo -e "${green}\n[V] ${end}Capturas de dominios_a_revisar realizadas correctamente."
        cat "$PROGRAMS_DIR/$program/Data/Domains/dominios_crt_sh.txt" 2>/dev/null | "$TOOLS_DIR/aquatone" --ports xlarge -out "$PROGRAMS_DIR/$program/Images/dominios_crt_sh" -chrome-path "$CHROMIUM_PATH" && echo -e "${green}\n[V] ${end}Capturas de dominios_crt_sh realizadas correctamente."
    else
        echo -e "${yellow}[!]${end} Chromium no encontrado. Saltando capturas de pantalla."
    fi
}

get_js() {
    echo -e "${red}\n[+]${end} Buscando archivos JS para su posterior análisis..."
    # Use dominios_vivos.txt if dominios_vivos_$date.txt doesn't exist yet (before new_domains runs)
    if [ -f "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos_$date.txt" ]; then
        subjs -i "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos_$date.txt" -ua "Firefox AppSec" -c 100 -t 5 2>/dev/null | sort -u >> "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt" && echo -e "${green}\n[V] ${end}Archivos JS obtenidos correctamente."
    elif [ -f "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt" ]; then
        subjs -i "$PROGRAMS_DIR/$program/Data/Domains/dominios_vivos.txt" -ua "Firefox AppSec" -c 100 -t 5 2>/dev/null | sort -u >> "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt" && echo -e "${green}\n[V] ${end}Archivos JS obtenidos correctamente."
    else
        echo -e "${yellow}[!]${end} No se encontró archivo de dominios vivos. Saltando este paso."
        touch "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt"
    fi
}

get_tokens() {
    echo -e "${red}\n[+]${end} Buscando API Keys de Google, Amazon, Twilio, etc a partir de archivos JS"
    if [ -f "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt" ] && [ -s "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt" ]; then
        cat "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt" | "$TOOLS_DIR/zile.py" --request 2>/dev/null | sort -u >> "$PROGRAMS_DIR/$program/Data/Domains/all_tokens.txt" && echo -e "${green}\n[V] ${end}Tokens obtenidos correctamente."
    else
        echo -e "${yellow}[!]${end} No se encontraron archivos JS. Saltando este paso."
        touch "$PROGRAMS_DIR/$program/Data/Domains/all_tokens.txt"
    fi
}

get_endpoints() {
    echo -e "${red}\n[+]${end} Buscando endpoints a partir de archivos JS"
    if [ -f "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt" ] && [ -s "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt" ]; then
        for url in $(cat "$PROGRAMS_DIR/$program/Data/Domains/all_jslinks.txt"); do
            filename=$(echo "${url##*/}").txt
            python3 "$TOOLS_DIR/LinkFinder/linkfinder.py" -i "$url" -o cli 2>/dev/null >> "$PROGRAMS_DIR/$program/Directories/js_endpoints/$filename"
        done
        echo -e "${green}\n[V] ${end}Endpoints obtenidos correctamente."
    else
        echo -e "${yellow}[!]${end} No se encontraron archivos JS. Saltando este paso."
    fi
}

scan_nuclei(){
    echo -e "${red}\n[+]${end} Comenzando escaneo con Nuclei..."
    nuclei -l "$PROGRAMS_DIR/$program/Data/Domains/dominios_a_revisar.txt" -o "$PROGRAMS_DIR/$program/Data/nuclei_results_suspects_domains.txt"
}

send_alert1(){
    echo -e "${red}\n[+]${end} Enviando alerta..."
    nuevos_dominios=$(cat "$PROGRAMS_DIR/$program/Data/Domains/nuevos_dominios_$date.txt")
    message="[ + ] ActiveRecon Alert:
    [ --> ] Nuevos dominios encontrados en el programa: $program
    $nuevos_dominios"
    curl --silent --output /dev/null -F chat_id="$chat_ID" -F "text=$message" "https://api.telegram.org/bot$bot_token/sendMessage" -X POST && echo -e "${green}\n[V] ${end}Alerta enviada!."
}

send_alert2(){
    echo -e "${red}\n[+]${end} Enviando alerta..."
    vulnerable_open_redirect=$(cat "$PROGRAMS_DIR/$program/Data/vulnerable_open_redirect.txt")
    message="[ + ] ActiveRecon Alert:
    [ --> ] URLs vulnerables a Open Redirect encontradas en el programa: $program
    $vulnerable_open_redirect"
    curl --silent --output /dev/null -F chat_id="$chat_ID" -F "text=$message" "https://api.telegram.org/bot$bot_token/sendMessage" -X POST && echo -e "${green}\n[V] ${end}Alerta enviada!."
}

helpPanel(){
    echo -e "${red}\n[X]${end} Debe ingresar los parametros:"
    echo -e "       -p / --program --> Escriba el nombre del programa"
    echo -e "       -f / --file --> Cree un archivo target_{program}.txt con los dominios y coloquelo en $TARGETS_DIR"
}

parameter_counter=0

while getopts ":p:f:" arg; do
    case $arg in
        p) program=$OPTARG && let parameter_counter+=1;;
        f) file=$OPTARG && file=$(basename "$file") && let parameter_counter+=1;;
    esac
done

if [ "$file" ] && [ "$program" ]; then
    check_dependencies
    main
else
    helpPanel
fi


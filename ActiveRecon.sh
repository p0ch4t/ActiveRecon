#!/bin/bash

# Colours
red="\e[31m"
green="\e[32m"
yellow="\e[33m"
end="\e[0m"

# Banner
echo -e $red"
 _______  _______ __________________          _______  _______  _______  _______  _______  _
(  ___  )(  ____ \\__   __/\__   __/|\     /|(  ____ \(  ____ )(  ____ \(  ____ \(  ___  )( (    /|
| (   ) || (    \/   ) (      ) (   | )   ( || (    \/| (    )|| (    \/| (    \/| (   ) ||  \  ( |
| (___) || |         | |      | |   | |   | || (__    | (____)|| (__    | |      | |   | ||   \ | |
|  ___  || |         | |      | |   ( (   ) )|  __)   |     __)|  __)   | |      | |   | || (\ \) |
| (   ) || |         | |      | |    \ \_/ / | (      | (\ (   | (      | |      | |   | || | \   |
| )   ( || (____/\   | |   ___) (___  \   /  | (____/\| ) \ \__| (____/\| (____/\| (___) || )  \  |
|/     \|(_______/   )_(   \_______/   \_/   (_______/|/   \__/(_______/(_______/(_______)|/    )_)

by: @p0ch4t - <joaquin.pochat@istea.com.ar>

"$end

# Environment Variables
bot_token=$(printenv bot_telegram_token)
chat_ID=$(printenv chat_ID)
date=$(date '-I')
cookies='ssid=ghy-121418-5Yg1lZa0i4X1UyUY75xJbULmxChVSm-__-1150111841-__-1765663848576--RRR_0-RRR_0' ## --> Setee sus cookies: Ej: session_id=test123;privelege=admin
authorization_token='' ## --> Setee su Authorization Token. Ej: Bearer ey1231234....
WORD_RESPONSE='ghy-121418-5Yg1lZa0i4X1UyUY75xJbULmxChVSm-__-1150111841-__-1765663848576--RRR_0-RRR_0' ## --> Setee una palabra. Esto sirve para buscar tokens de sesion en respuestas del servidor (para usar con XSS)

# Functions

check_root(){
	if [ "$(id -u)" != "0" ]; then
		echo -e $red"[X] Este programa solo puede ejecutarse siendo ROOT!"$end
		exit 1
	fi
}

check_dependencies(){
	echo -e $green"[+] "$end"Chequeando dependencias...\n"
    mkdir -p /opt/tools_ActiveRecon
    mkdir -p /opt/BugBounty/Programs
    mkdir -p /opt/BugBounty/Targets
	export PATH="$PATH:/opt/tools_ActiveRecon:/root/go/bin"
	dependencies=(go unzip findomain assetfinder amass subfinder httpx ScanOpenRedirect.py gau aquatone nuclei zile.py linkfinder.py unfurl subjs dirsearch.py sub404.py)
	for dependency in "${dependencies[@]}"; do
		which $dependency > /dev/null 2>&1
		if [ "$(echo $?)" -ne "0" ]; then
			echo -e $red"[X] $dependency "$end"no esta instalado."
			case $dependency in
                go)
                    wget -q --show-progress http://mirror.archlinuxarm.org/aarch64/community/go-2:1.19.4-1-aarch64.pkg.tar.xz -O /golang.tar.xz && tar -xf /golang.tar.xz -C 2>/dev/null / && rm /golang.tar.xz && echo "export PATH=$PATH:/root/go/bin" >> /root/.bashrc && echo -e $green"[+] "$end"Golang instalado!"
                    ;;
                unzip)
                    wget -q --show-progress http://mirror.archlinuxarm.org/aarch64/extra/unzip-6.0-19-aarch64.pkg.tar.xz -O /unzip.tar.xz && tar -xf /unzip.tar.xz -C 2>/dev/null / && rm /unzip.tar.xz && echo -e $green"[+] "$end"Unzip instalado!"
                    ;;
				findomain)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					wget -q --show-progress https://github.com/Findomain/Findomain/releases/download/8.2.1/findomain-aarch64.zip -O /opt/tools_ActiveRecon/findomain.zip && unzip -qq /opt/tools_ActiveRecon/findomain.zip -d /opt/tools_ActiveRecon/ && rm /opt/tools_ActiveRecon/findomain.zip && chmod +x /opt/tools_ActiveRecon/findomain && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				assetfinder)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					go install github.com/tomnomnom/assetfinder@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				amass)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					go install github.com/OWASP/Amass/v3/cmd/amass@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				subfinder)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				httpx)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					go install github.com/projectdiscovery/httpx/cmd/httpx@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
                ScanOpenRedirect.py)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    wget -q --show-progress https://raw.githubusercontent.com/p0ch4t/ScanOpenRedirect/main/ScanOpenRedirect.py -O /opt/tools_ActiveRecon/ScanOpenRedirect.py && chmod +x /opt/tools_ActiveRecon/ScanOpenRedirect.py && sed -i '1s/^/#!\/usr\/bin\/python3\n/' /opt/tools_ActiveRecon/ScanOpenRedirect.py && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
                gau)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					go install github.com/lc/gau/v2/cmd/gau@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				aquatone)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					wget -q --show-progress https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_arm64_1.7.0.zip -O /opt/tools_ActiveRecon/aquatone.zip && unzip -q /opt/tools_ActiveRecon/aquatone.zip -d /opt/tools_ActiveRecon && rm /opt/tools_ActiveRecon/aquatone.zip /opt/tools_ActiveRecon/README.md /opt/tools_ActiveRecon/LICENSE.txt && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
                nuclei)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
				zile.py)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					wget https://raw.githubusercontent.com/bonino97/new-zile/master/zile.py -q --show-progress -O /opt/tools_ActiveRecon/zile.py && chmod +x /opt/tools_ActiveRecon/zile.py && sed -i '1s/^/#!\/usr\/bin\/python3\n/' /opt/tools_ActiveRecon/zile.py && pip3 install termcolor -q && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				linkfinder.py)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					git clone -q https://github.com/GerbenJavado/LinkFinder.git /opt/tools_ActiveRecon/LinkFinder && pip3 install -r /opt/tools_ActiveRecon/LinkFinder/requirements.txt -q && ln -s /opt/tools_ActiveRecon/LinkFinder/linkfinder.py /opt/tools_ActiveRecon/linkfinder.py && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
                unfurl)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    go install github.com/tomnomnom/unfurl@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
                    ;;
				subjs)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					go install github.com/lc/subjs@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				dirsearch.py)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					wget -q --show-progress https://github.com/maurosoria/dirsearch/archive/refs/tags/v0.4.0.zip -O /opt/tools_ActiveRecon/dirsearch.zip && unzip -q /opt/tools_ActiveRecon/dirsearch.zip -d /opt/tools_ActiveRecon/ && rm /opt/tools_ActiveRecon/dirsearch.zip && ln -s /opt/tools_ActiveRecon/dirsearch-0.4.0/dirsearch.py /opt/tools_ActiveRecon/dirsearch.py && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				sub404.py)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					git clone -q https://github.com/r3curs1v3-pr0xy/sub404.git /opt/tools_ActiveRecon/sub404 && pip3 install -r /opt/tools_ActiveRecon/sub404/requirements.txt -q && ln -s /opt/tools_ActiveRecon/sub404/sub404.py /opt/tools_ActiveRecon/sub404.py && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
			esac
		else
			echo -e $green"[V] $dependency"$end
		fi
	done
}

main(){
    # Validaciones
    ls /opt/BugBounty/Targets/$file > /dev/null 2>&1
    if [[ "$(echo $?)" != "0" ]]; then
        echo -e $red"\n[X]"$end $bold"No se encontr?? '$file'. Cree un archivo target_{program}.txt con los principales dominios en la ruta /opt/BugBounty/Targets/"$end && exit 1
    fi
    file=/opt/BugBounty/Targets/$file
    mkdir -p /opt/BugBounty/Programs/$program/Directories/js_endpoints/
    mkdir -p /opt/BugBounty/Programs/$program/Directories/dirsearch_endpoints/
    mkdir -p /opt/BugBounty/Programs/$program/Images/dominios_crt_sh
    mkdir -p /opt/BugBounty/Programs/$program/Images/dominios_a_revisar_$date
    mkdir -p /opt/BugBounty/Programs/$program/Data/Domains
    cd /opt/BugBounty/Programs/$program/Data/Domains
    get_domains
    get_alive
    get_subdomain_takeover
    get_all_urls
    get_suspects_files
    get_open_redirects
    scan_open_redirect
    get_especial_domains
    if [[ $TOKEN_SESSION ]]; then
        find_token_session_on_response
    fi
    get_paths
    get_js
    get_tokens
    get_endpoints
    new_domains
    get_aquatone
    scan_nuclei
    find /opt/BugBounty/Programs/$program/ -type f -empty -delete
}

get_domains() {
    echo -e $red"\n[+]"$end $bold"Escaneo de dominios..."$end
    findomain -f $file -r -u findomain_domains.txt
    cat $file | assetfinder --subs-only | tee -a assetfinder_domains.txt
    amass enum -df $file -passive -o ammas_passive_domains.txt
    subfinder -dL $file -o subfinder_domains.txt
    sort -u *_domains.txt -o subdomains.txt
    cat subdomains.txt | rev | cut -d . -f 1-3 | rev | sort -u | tee root_subdomains.txt
    cat *.txt | unfurl domains | sort -u > all_domains.txt
    find . -type f -not -name 'all_domains.txt' -delete
    number_domains=$(wc -l /opt/BugBounty/Programs/$program/Data/Domains/all_domains.txt)
    echo -e $green"\n[V] "$end"Escaneo finalizado. Dominios obtenidos: $number_domains"
}

get_alive() {
    echo -e $red"\n[+]"$end $bold"Escaneo de dominios vivos..."$end

    cat all_domains.txt | httpx -t 200 -silent -timeout 3 -H "User-Agent: Firefox AppSec" -H "Cookie: $cookies" -H "Authorization: $authorization_token" > /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt
    number_domains=$(wc -l /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt)

    echo -e $green"\n[V] "$end"Escaneo finalizado. Dominios vivos: $number_domains"
}

get_subdomain_takeover(){
	echo -e $red"\n[+]"$end $bold"Escaneo en busqueda de subdomains takeovers"$end
	python3 /opt/tools_ActiveRecon/sub404/sub404.py -f /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt | grep -P "Reading file|Total Unique Subdomain|URL Checked|Vulnerability Possible" | tee -a /opt/BugBounty/Programs/$program/Data/possible_subdomains_takeover.txt
}

get_all_urls() {
    echo -e $red"\n[+]"$end $bold"Escaneo de dominios en Waybackurl, Commoncrawl, Otx y Urlscan. Esto puede demorar bastante..."$end
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt | gau --threads 100 --timeout 10 --fp --retries 3 > /opt/BugBounty/Programs/$program/Data/Domains/all_urls.txt
    number_domains=$(wc -l /opt/BugBounty/Programs/$program/Data/Domains/all_urls.txt)
    echo -e $green"\n[V] "$end"URLs obtenidas correctamente. Cantidad de URLs obtenidas: $number_domains"
}

get_suspects_files(){
    echo -e $red"\n[+]"$end $bold"Buscando URLs con files php, aspx, jsp, ruby y perl"$end
    cat all_urls.txt | grep -P "\w+\.(php|aspx|jsp|pl|rb)(\?|$)" | sort -u > dominios_a_analizar
    for url in $(cat dominios_a_analizar); do
        dominio_path=$(echo $url | unfurl format %d%p)
        cat dominios_a_analizar | grep $dominio_path | head -n1 >> /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar_$date.txt
    done
    sort -u /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar_$date.txt -o /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar_$date.txt
    rm -f dominios_a_analizar
    echo -e $green"\n[V] "$end"Escaneo finalizado!"
}

get_open_redirects() {
    echo -e $red"\n[+]"$end $bold"Buscando URLs susceptibles a Open Redirect"$end
    cat /opt/BugBounty/Programs/$program/Data/Domains/all_urls.txt | sort -u | grep -P "(%253D|%3D|=)http(s|)(%253A|%3A|:)(%252F|%2F|\/)(%252F|%2F|\/)[A-Za-z0-9-]+\." | httpx -t 200 -silent -timeout 3 -mc 301,302 -H "User-Agent: Firefox AppSec" -H "Cookie: $cookies" -H "Authorization: $authorization_token" | tee -a /opt/BugBounty/Programs/$program/Data/possible_open_redirect.txt
    number_domains=$(wc -l /opt/BugBounty/Programs/$program/Data/possible_open_redirect.txt)
    echo -e $green"\n[V] "$end"Busqueda finalizada! Dominios obtenidos: $number_domains"
}

scan_open_redirect(){
    echo -e $red"\n[+]"$end $bold"Comenzando escaneo Open Redirect..."$end
    ScanOpenRedirect.py -f /opt/BugBounty/Programs/$program/Data/possible_open_redirect.txt -c "$cookies"
    mv /opt/BugBounty/Programs/$program/Data/Domains/vulnerable_open_redirect.txt /opt/BugBounty/Programs/$program/Data/ 2>/dev/null
    mv /opt/BugBounty/Programs/$program/Data/Domains/otros_posibles_dom_open_redirect.txt.txt /opt/BugBounty/Programs/$program/Data/ 2>/dev/null
    if [[ "$(wc -w /opt/BugBounty/Programs/$program/Data/vulnerable_open_redirect.txt 2>/dev/null | cut -d ' ' -f1)" > "0" ]]; then
        echo -e $green"\n[V] "$end"URLs vulnerables encontradas!." && send_alert2
    else
        rm -f /opt/BugBounty/Programs/$program/Data/vulnerable_open_redirect.txt
    fi
    echo -e $green"\n[V] "$end"Escaneo finalizado!"
}

find_token_session_on_response(){
    echo -e $red"\n[+]"$end $bold"Buscando '$WORD_RESPONSE' en las respuestas del servidor"$end
    cat /opt/BugBounty/Programs/$program/Data/Domains/all_urls.txt | httpx -silent -t 200 -timeout 3 -ms "$WORD_RESPONSE" -H "User-Agent: Firefox AppSec" -H "Cookie: $cookies" -H "Authorization: $authorization_token" > /opt/BugBounty/Programs/$program/Data/tokens_on_response.txt
    echo -e $green"\n[V] "$end"Escaneo finalizado!"
}

get_especial_domains(){
    echo -e $red"\n[+]"$end $bold"Busqueda especial de dominios con Crt.sh"$end
    rm -f /opt/BugBounty/Programs/$program/Data/Domains/dominios_crt_sh.txt
    organization_names=()
    echo -e $yellow"\n[*]"$end $bold"Certificados:"$end
    for dominio in $(cat "/opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt"); do
        name=$(curl -s 'https://www.digicert.com/api/check-host.php' --data-raw "host=$dominio" | grep -E -oh "Organization = [A-Za-z0-9. ]+" | cut -d "=" -f2 | sed 's/^[[:space:]]//g')
        if [[ ! "${organization_names[*]}" =~ "${name}" ]]; then
            echo "$name - $dominio"
            echo $dominio >> /opt/BugBounty/Programs/$program/Data/Domains/dominios_crt_sh.txt
            organization_names+=$name
        fi
    done
    echo -e $green"\n[V] "$end"Busqueda finalizada! Guardados en: /opt/BugBounty/Programs/$program/Data/dominios_crt_sh.txt"
}

get_paths() {
    echo -e $red"\n[+]"$end $bold"Busqueda de directorios con 'dirsearch' de dominios a revisar"$end
    domains=()
    for url in $(cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar_$date.txt); do
        domain=$(echo $url | unfurl format %d)
        if [[ ! "${domains[*]}" =~ "${domain}" ]]; then
            domains+=$domain
        fi
    done
    for host in ${domains[@]}; do
        dirsearch_file=$(echo $host | sed -E 's/[\.|\/|:]+/_/g').txt
        python3 /opt/tools_ActiveRecon/dirsearch-0.4.0/dirsearch.py -E -t 50 --plain-text /opt/BugBounty/Programs/$program/Directories/dirsearch_endpoints/$dirsearch_file -u $host -w /opt/tools_ActiveRecon/dirsearch-0.4.0/db/dicc.txt --user-agent="Firefox AppSec" --cookie="$cookies" | grep Target && tput sgr0
    done
    echo -e $green"\n[V] "$end"Busqueda finalizada!"
}

new_domains(){
    echo -e $red"\n[+]"$end $bold"Buscando diferencias de escaneos anteriores..."$end
    shopt -s extglob 2>/dev/null && result=$(cat !(/opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt) 2>/dev/null)
    lista_dominios=$(cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt)
    for dominio in $lista_dominios; do
         echo $result | grep $dominio > /dev/null 2>&1
        if [ "$(echo $?)" -ne "0" ]; then
            echo $dominio | tee -a /opt/BugBounty/Programs/$program/Data/Domains/nuevos_dominios_$date.txt
        fi
    done
    ls nuevos_dominios_$date.txt > /dev/null 2>&1 && echo -e $green"[V] "$end"Diferencias encontradas!." && send_alert1
}

get_aquatone() {
    echo -e $red"\n[+]"$end $bold"Sacando capturas de dominios a revisar..."$end
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar_$date.txt | aquatone --ports xlarge -out /opt/BugBounty/Programs/$program/Images/dominios_a_revisar_$date -scan-timeout 500 -screenshot-timeout 50000 -http-timeout 6000 -chrome-path /snap/bin/chromium
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_crt_sh.txt | aquatone --ports xlarge -out /opt/BugBounty/Programs/$program/Images/dominios_crt_sh -scan-timeout 500 -screenshot-timeout 50000 -http-timeout 6000 -chrome-path /snap/bin/chromium
    echo -e $green"\n[V] "$end"Capturas realizadas correctamente."
}

get_js() {
    echo -e $red"\n[+]"$end $bold"Buscando archivos JS para su posterior an??lisis..."$end
    subjs -i /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt -ua "Firefox AppSec" -c 100 -t 5 | sort -u >> all_jslinks.txt && echo -e $green"\n[V] "$end"Archivos JS obtenidos correctamente."
}

get_tokens() {
    echo -e $red"\n[+]"$end $bold"Buscando API Keys de Google, Amazon, Twilio, etc a partir de archivos JS"$end
    cat all_jslinks.txt | zile.py --request | sort -u >> all_tokens.txt && echo -e $green"\n[V] "$end"Tokens obtenidos correctamente."
}

get_endpoints() {
    echo -e $red"\n[+]"$end $bold"Buscando endpoints a partir de archivos JS"$end
    for link in $(cat all_jslinks.txt); do
        links_file=$(echo $link | unfurl format %d%p | sed -E 's/[\.|\/|:]+/_/g').txt
        python3 /opt/tools_ActiveRecon/LinkFinder/linkfinder.py -i $link -o cli >> /opt/BugBounty/Programs/$program/Directories/js_endpoints/$links_file
    done
    echo -e $green"\n[V] "$end"Endpoints obtenidos correctamente."
}

scan_nuclei(){
    echo -e $red"\n[+]"$end $bold"Comenzando escaneo con Nuclei..."$end
    nuclei -l /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar_$date.txt -t $HOME/nuclei-templates/cves/ -o /opt/BugBounty/Programs/$program/Data/nuclei_results_suspects_domains_$date.txt
    nuclei -l /opt/BugBounty/Programs/$program/Data/Domains/dominios_crt_sh.txt -t $HOME/nuclei-templates/cves/ -o /opt/BugBounty/Programs/$program/Data/nuclei_results_domains_crt_sh_$date.txt
}

send_alert1(){
    echo -e $red"\n[+]"$end $bold"Enviando alerta..."$end
    nuevos_dominios="cat nuevos_dominios_$date.txt"
    message="[ + ] ActiveRecon Alert:
    [ --> ] Nuevos dominios encontrados en el programa: $program
    $($nuevos_dominios)"
    curl --silent --output /dev/null -F chat_id="$chat_ID" -F "text=$message" "https://api.telegram.org/bot$bot_token/sendMessage" -X POST && echo -e $green"\n[V] "$end"Alerta enviada!."
}

send_alert2(){
    echo -e $red"\n[+]"$end $bold"Enviando alerta..."$end
    vulnerable_open_redirect="cat /opt/BugBounty/Programs/$program/Data/vulnerable_open_redirect.txt"
    message="[ + ] ActiveRecon Alert:
    [ --> ] URLs vulnerables a Open Redirect encontradas en el programa: $program
    $($vulnerable_open_redirect)"
    curl --silent --output /dev/null -F chat_id="$chat_ID" -F "text=$message" "https://api.telegram.org/bot$bot_token/sendMessage" -X POST && echo -e $green"\n[V] "$end"Alerta enviada!."
}

helpPanel(){
    echo -e $red"\n[X]"$end $bold"Debe ingresar los parametros:"$end
    echo -e "       -p / --program --> Escriba el nombre del programa"
    echo -e "       -f / --file --> Cree un archivo archivo target_{program}.txt con los dominios y coloquelo en /opt/BugBounty/Targets"
}

parameter_counter=0

while getopts ":p:f:" arg; do
    case $arg in
        p) program=$OPTARG && let parameter_counter+=1;;
        f) file=$OPTARG && file=$(basename $file) && let parameter_counter+=1;;
    esac
done

if [ $file ] && [ $program ]; then
    check_root
    check_dependencies
    main
else
    helpPanel
fi

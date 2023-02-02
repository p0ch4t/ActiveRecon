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
bot_token=$(printenv bot_telegram_token) ## Cree una variable de entorno con su bot token de telegram
chat_ID=$(printenv chat_ID) ## Cree una variable de entorno con su chat_ID de telegram
WPSCAN_API_TOKEN=$(printenv WPSCAN_API_TOKEN) ## Cree una variable de entorno con su API-TOKEN de WpScan
date=$(date '-I')
cookies='' ## --> Setee sus cookies: Ej: session_id=test123;privelege=admin
authorization_token='' ## --> Setee su Authorization Token. Ej: Bearer ey1231234....
WORD_RESPONSE='' ## --> Setee una palabra. Esto sirve para buscar tokens de sesion en respuestas del servidor (para usar con XSS)

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
	dependencies=(docker go unzip pip3 chromium findomain assetfinder amass subfinder httpx ScanOpenRedirect.py gau waybackurls aquatone nuclei zile.py linkfinder.py unfurl subjs dirsearch subjack)
	for dependency in "${dependencies[@]}"; do
		which $dependency > /dev/null 2>&1
		if [ "$(echo $?)" -ne "0" ]; then
			echo -e $red"[X] $dependency "$end"no esta instalado."
			case $dependency in
                docker)
                    snap install docker &> /dev/null && docker pull wpscanteam/wpscan &> /dev/null
                    ;;            
                go)
                    snap install golang --classic &> /dev/null && export PATH=$PATH:/root/go/bin && echo 'export PATH=$PATH:/root/go/bin' >> /root/.bashrc
                    ;;
                unzip)
                    apt install unzip -y &> /dev/null
                    ;;
                pip3)
                    apt install python3-pip -y &> /dev/null
                    ;;
                chromium)
                    snap install chromium
                    ;;
                apache2)
                    apt install apache2 -y &> /dev/null && echo "DirectoryIndex aquatone_report.html" >> "/etc/apache2/apache2.conf" && systemctl restart apache2
                    # Permite el tráfico desde el firewall local
                    iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
                    netfilter-persistent save
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
                waybackurls)
                    echo -e "${yellow}[..]${end} Instalando $dependency"
                    go install github.com/tomnomnom/waybackurls@latest &> /dev/null && echo -e "${green}[V] $dependency${end} instalado correctamente!"
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
				dirsearch)
					echo -e "${yellow}[..]${end} Instalando $dependency"
					pip3 install dirsearch -q && echo -e "${green}[V] $dependency${end} instalado correctamente!"
					;;
				subjack)
					echo -e "${yellow}[..]${end} Instalando $dependency"
                    go install github.com/haccer/subjack@latest &> /dev/null && mkdir -p /src/github.com/haccer/subjack && wget -q "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" -O /src/github.com/haccer/subjack/fingerprints.json && echo -e "${green}[V] $dependency${end} instalado correctamente!"
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
        echo -e $red"\n[X]"$end $bold"No se encontró '$file'. Cree un archivo target_{program}.txt con los principales dominios en la ruta /opt/BugBounty/Targets/"$end && exit 1
    fi
    file=/opt/BugBounty/Targets/$file
    mkdir -p /opt/BugBounty/Programs/$program/Directories/js_endpoints/
    mkdir -p /opt/BugBounty/Programs/$program/Directories/dirsearch_endpoints/
    mkdir -p /opt/BugBounty/Programs/$program/Images/dominios_crt_sh
    mkdir -p /opt/BugBounty/Programs/$program/Images/dominios_a_revisar
    mkdir -p /opt/BugBounty/Programs/$program/Data/Domains
    mkdir -p /var/www/html/$program
    cd /opt/BugBounty/Programs/$program/Data/Domains
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
    find /opt/BugBounty/Programs/$program/ -type f -empty -delete
}

get_domains() {
    echo -e $red"\n[+]"$end $bold"Escaneo de dominios..."$end
    findomain -f $file -r -u findomain_domains
    cat $file | assetfinder --subs-only | tee -a assetfinder_domains
    amass enum -df $file -passive -o ammas_passive_domains
    subfinder -dL $file -o subfinder_domains
    sort -u *_domains -o subdomains
    cat subdomains | rev | cut -d . -f 1-3 | rev | sort -u | tee root_subdomains
    cat * | unfurl domains | sort -u > all_domains
    for domain in $(cat $file); do
        cat all_domains | grep $domain | unfurl format %s://%d%p | sort -u >> all_domains.txt
    done
    find . -type f -not -name '*.txt' -delete
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
	subjack -w /opt/BugBounty/Programs/$program/Data/Domains/all_domains.txt -t 100 -timeout 30 -o /opt/BugBounty/Programs/$program/Data/possible_subdomains_takeover.txt
}

get_all_urls() {
    echo -e $red"\n[+]"$end $bold"Escaneo de dominios en Waybackurl, Commoncrawl, Otx y Urlscan. Esto puede demorar bastante..."$end
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt | gau --threads 100 --timeout 10 --fp --retries 3 > /opt/BugBounty/Programs/$program/Data/Domains/all_urls
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt | waybackurls >> /opt/BugBounty/Programs/$program/Data/Domains/all_urls
    for domain in $(cat $file); do
        cat all_urls | grep $domain | unfurl format %s://%d%p | grep -vi -P "png|jpg|jpeg|gif|pdf|mp4|svg|ttf|eot|woff|woff2|css" | sort -u >> all_urls.txt
    done
    number_domains=$(wc -l /opt/BugBounty/Programs/$program/Data/Domains/all_urls.txt)
    rm all_urls
    echo -e $green"\n[V] "$end"URLs obtenidas correctamente. Cantidad de URLs obtenidas: $number_domains"
}

get_suspects_files(){
    echo -e $red"\n[+]"$end $bold"Buscando URLs con files php, aspx, jsp, ruby y perl"$end
    cat all_urls.txt | grep -P "\w+\.(php|aspx|jsp|pl|rb)(\?|$)" | sort -u > dominios_a_analizar
    for url in $(cat dominios_a_analizar); do
        dominio_path=$(echo $url | unfurl format %d%p)
        cat dominios_a_analizar | grep $dominio_path | head -n1 >> /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar.txt
    done
    sort -u /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar.txt -o /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar.txt
    rm -f dominios_a_analizar
    echo -e $green"\n[V] "$end"Escaneo finalizado!"
}

scan_wordpress_domains(){
    echo -e $red"\n[+]"$end $bold"Iniciando reconocimiento y escaneo de sitios Wordpress"$end
    cat dominios_a_revisar.txt | unfurl format %s://%d | httpx -silent -tech-detect | grep -i Wordpress | cut -d " " -f1 > revision_domains
    cat revision_domains all_domains.txt | sort -u | httpx -silent -tech-detect | grep -i Wordpress | cut -d " " -f1 > wordpress_domains.txt
    for url in $(cat wordpress_domains.txt); do
        if [[ $WPSCAN_API_TOKEN ]]; then
            docker run -it --rm wpscanteam/wpscan --url $url --exclude-content-based --force --random-user-agent --api-token $WPSCAN_API_TOKEN --enumerate | tee -a wordpress_scan.txt
        else
            docker run -it --rm wpscanteam/wpscan --url $url --exclude-content-based --force --random-user-agent --enumerate | tee -a wordpress_scan.txt
        fi
    done
    rm revision_domains
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
            #echo $dominio >> /opt/BugBounty/Programs/$program/Data/Domains/dominios_crt_sh.txt
            name=$(echo $name | sed 's/\s/\+/g')
            echo "https://crt.sh/?q=$name&dominio_encontrado=$dominio" >> /opt/BugBounty/Programs/$program/Data/Domains/dominios_crt_sh.txt
            organization_names+=$name
        fi
    done
    echo -e $green"\n[V] "$end"Busqueda finalizada! Guardados en: /opt/BugBounty/Programs/$program/Data/dominios_crt_sh.txt"
}

get_paths() {
    echo -e $red"\n[+]"$end $bold"Busqueda de directorios con 'dirsearch' de dominios a revisar"$end
    domains=()
    for url in $(cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar.txt); do
        domain=$(echo $url | unfurl format %d)
        if [[ ! "${domains[*]}" =~ "${domain}" ]]; then
            domains+="$domain "
        fi
    done
    for host in ${domains[@]}; do
        dirsearch_file=$(echo "${host##*/}").txt
        dirsearch -e php,aspx,jsp,pl,rb -t 50 -u $host --user-agent="Firefox AppSec" --cookie="$cookies" --header="Authorization: $authorization_token" --format plain -o /opt/BugBounty/Programs/$program/Data/Directories/$dirsearch_file | grep Target && tput sgr0
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
    echo -e $red"\n[+]"$end $bold"Sacando capturas de dominios..."$end
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt | aquatone --ports xlarge -out /opt/BugBounty/Programs/$program/Images/dominios_vivos -chrome-path /snap/bin/chromium && echo -e $green"\n[V] "$end"Capturas de dominios_vivos_$date realizadas correctamente."
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar.txt | aquatone --ports xlarge -out /opt/BugBounty/Programs/$program/Images/dominios_a_revisar -chrome-path /snap/bin/chromium && echo -e $green"\n[V] "$end"Capturas de dominios_a_revisar realizadas correctamente."
    cat /opt/BugBounty/Programs/$program/Data/Domains/dominios_crt_sh.txt | aquatone --ports xlarge -out /opt/BugBounty/Programs/$program/Images/dominios_crt_sh -chrome-path /snap/bin/chromium && echo -e $green"\n[V] "$end"Capturas de dominios_crt_sh realizadas correctamente."
    rm -rf /var/www/html/$program/*
    cp -r /opt/BugBounty/Programs/$program/Images/* /var/www/html/$program/
}

get_js() {
    echo -e $red"\n[+]"$end $bold"Buscando archivos JS para su posterior análisis..."$end
    subjs -i /opt/BugBounty/Programs/$program/Data/Domains/dominios_vivos_$date.txt -ua "Firefox AppSec" -c 100 -t 5 | sort -u >> all_jslinks.txt && echo -e $green"\n[V] "$end"Archivos JS obtenidos correctamente."
}

get_tokens() {
    echo -e $red"\n[+]"$end $bold"Buscando API Keys de Google, Amazon, Twilio, etc a partir de archivos JS"$end
    cat all_jslinks.txt | zile.py --request | sort -u >> all_tokens.txt && echo -e $green"\n[V] "$end"Tokens obtenidos correctamente."
}

get_endpoints() {
    echo -e $red"\n[+]"$end $bold"Buscando endpoints a partir de archivos JS"$end
    for url in $(cat all_jslinks.txt); do
        filename=$(echo "${url##*/}").txt
        python3 /opt/tools_ActiveRecon/LinkFinder/linkfinder.py -i $url -o cli >> /opt/BugBounty/Programs/$program/Directories/js_endpoints/$filename
    done
    echo -e $green"\n[V] "$end"Endpoints obtenidos correctamente."
}

scan_nuclei(){
    echo -e $red"\n[+]"$end $bold"Comenzando escaneo con Nuclei..."$end
    nuclei -l /opt/BugBounty/Programs/$program/Data/Domains/dominios_a_revisar.txt -o /opt/BugBounty/Programs/$program/Data/nuclei_results_suspects_domains.txt
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

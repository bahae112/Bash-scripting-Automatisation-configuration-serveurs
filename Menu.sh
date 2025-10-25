#!/bin/bash

ldapPassword=test
myDomain=Ehtp.Equipe1
Organization=Ehtp.Equipe1
systemPassword=test

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # Pas de couleur
configure_dhcp() {
    echo -e "${YELLOW}Configuration de DHCP avec dnsmasq...${NC}"

    # Mise  jour des paquets et installation de dnsmasq
    sudo apt-get update
    sudo apt-get install -y dnsmasq

    # Utilisation de Zenity pour afficher un formulaire avec plusieurs champs
    result=$(zenity --forms --title="Configuration DHCP" \
        --text="Veuillez remplir les informations suivantes" \
        --width=500 --height=500 \
        --add-entry="Interface reseau (ex. eth0)" \
        --add-entry="Reseau (ex. 192.168.137.0)" \
        --add-entry="Masque de sous-reseau (ex. 255.255.255.0)" \
        --add-entry="Adresse IP debut plage DHCP (ex. 192.168.137.50)" \
        --add-entry="Adresse IP fin plage DHCP (ex. 192.168.137.100)" \
        --add-entry="Duree du bail (ex. 12h)" \
        --add-entry="Passerelle (ex. 192.168.137.1)" \
        --add-entry="Serveur DNS principal (ex. 192.168.137.1)" \
        --add-entry="Serveur DNS secondaire (facultatif)" \
        --add-entry="Serveur DNS public supplementaire (facultatif)" \
        --add-entry="Autre serveur DNS public (facultatif)")

    if [ $? -ne 0 ]; then
        echo "L utilisateur a annule l'operation."
        exit 1
    fi

    # Extraire les valeurs du formulaire
    IFS="|" read -r interface network netmask dhcp_start dhcp_end lease_time gateway dns_primary dns_secondary public_dns_1 public_dns_2 <<< "$result"


    echo "Interface: $interface"
    echo "Reseau: $network"
    echo "Masque: $netmask"
    echo "Debut DHCP: $dhcp_start"
    echo "Fin DHCP: $dhcp_end"
    echo "Duree du bail: $lease_time"
    echo "Passerelle: $gateway"
    echo "DNS primaire: $dns_primary"
    echo "DNS secondaire: $dns_secondary"
    echo "DNS public 1: $public_dns_1"
    echo "DNS public 2: $public_dns_2"

    # Creation du fichier dnsmasq.conf avec les valeurs fournies par l'utilisateur
    echo "Modification du fichier /etc/dnsmasq.conf..."
    sudo bash -c "echo '# Interface reseau utilisee par dnsmasq' > /etc/dnsmasq.conf"
    sudo bash -c "echo 'interface=$interface' >> /etc/dnsmasq.conf"
    sudo bash -c "echo 'dhcp-range=$dhcp_start,$dhcp_end,$lease_time' >> /etc/dnsmasq.conf"

    # Ajouter la configuration de la passerelle par defaut
    sudo bash -c "echo 'dhcp-option=option:router,$gateway' >> /etc/dnsmasq.conf"

    # Ajouter la configuration du serveur DNS principal
    sudo bash -c "echo 'dhcp-option=option:dns-server,$dns_primary' >> /etc/dnsmasq.conf"

    # Ajouter la configuration du serveur DNS secondaire, si renseigne
    if [ -n "$dns_secondary" ]; then
        sudo bash -c "echo 'dhcp-option=option:dns-server,$dns_secondary' >> /etc/dnsmasq.conf"
    fi

    # Ajouter les serveurs DNS publics, si renseignes
    if [ -n "$public_dns_1" ]; then
        sudo bash -c "echo 'server=$public_dns_1' >> /etc/dnsmasq.conf"
    fi
    if [ -n "$public_dns_2" ]; then
        sudo bash -c "echo 'server=$public_dns_2' >> /etc/dnsmasq.conf"
    fi

    # Ajouter la configuration du port DHCP
    sudo bash -c "echo 'port=5353' >> /etc/dnsmasq.conf"

    echo "Redemarrage de dnsmasq..."
    sudo systemctl restart dnsmasq

    echo -e "${GREEN}Configuration DHCP terminee !${NC}"
}


configure_dns_master() {
    echo -e "${YELLOW}Configuration de DNS avec BIND9...${NC}"
    sudo apt-get update
    sudo apt-get install -y bind9

    # Utilisation de Zenity pour demander les informations a l'utilisateur dans un formulaire
    result=$(zenity --forms --title="Configuration DNS" \
                    --text="Entrez les informations pour configurer le DNS" \
                    --add-entry="Domaine (ex: example.com)" \
                    --add-entry="Adresse IP (ex: 192.168.1.100)" \
                    --add-entry="Nom du serveur (ex: ns1)")

    # Verification si l'utilisateur a annule ou laisse des champs vides
    if [[ $? -ne 0 ]]; then
        zenity --error --text="L'utilisateur a annule l'entree."
        return
    fi

    # Separation des valeurs saisies dans le formulaire
    domain=$(echo $result | cut -d'|' -f1)
    ip_address=$(echo $result | cut -d'|' -f2)
    server_name=$(echo $result | cut -d'|' -f3)

    # Verification de la validite des entrees
    if [[ -z "$domain" || -z "$ip_address" || -z "$server_name" ]]; then
        zenity --error --text="Tous les champs sont obligatoires."
        return
    fi

    echo "Creation des fichiers de zones..."
    sudo touch /etc/bind/forward.db /etc/bind/reverse.db
    echo "Modification du fichier named.conf.local..."

    # Calcul de la zone inverse a partir de l'adresse IP
    reverse_network=$(echo $ip_address | awk -F'.' '{print $3"."$2"."$1}')

    # Ajout du contenu dans /etc/bind/named.conf.local
    sudo bash -c "echo 'zone \"$domain\" IN {' > /etc/bind/named.conf.local"
    sudo bash -c "echo '    type master;' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    file \"/etc/bind/forward.db\";' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    allow-update { none; };' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '};' >> /etc/bind/named.conf.local"

    # Configuration du reverse zone (inversion de l'adresse IP pour la zone inverse)
    reverse_zone=$(echo $ip_address | awk -F'.' '{print $3"."$2"."$1}')
    sudo bash -c "echo 'zone \"$reverse_zone.in-addr.arpa\" {' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    type master;' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    file \"/etc/bind/reverse.db\";' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    allow-update { none; };' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '};' >> /etc/bind/named.conf.local"

    echo "Configuration des fichiers de zones..."

    # Ajout du contenu dans /etc/bind/forward.db
    sudo bash -c "echo '\$TTL    604800' > /etc/bind/forward.db"
    sudo bash -c "echo '@       IN      SOA     $server_name.$domain. root.$server_name.$domain. (' >> /etc/bind/forward.db"
    sudo bash -c "echo '                          8         ; Serial' >> /etc/bind/forward.db"
    sudo bash -c "echo '                     604800         ; Refresh' >> /etc/bind/forward.db"
    sudo bash -c "echo '                      86400         ; Retry' >> /etc/bind/forward.db"
    sudo bash -c "echo '                    2419200         ; Expire' >> /etc/bind/forward.db"
    sudo bash -c "echo '                     604800 )       ; Negative Cache TTL' >> /etc/bind/forward.db"
    sudo bash -c "echo '@       IN      NS      $server_name.$domain.' >> /etc/bind/forward.db"
    sudo bash -c "echo '$server_name.$domain.     IN      A       $ip_address' >> /etc/bind/forward.db"

    # Ajout du contenu dans /etc/bind/reverse.db
    sudo bash -c "echo '\$TTL    604800' > /etc/bind/reverse.db"
    sudo bash -c "echo '@       IN      SOA     $server_name.$domain. root.$server_name.$domain. (' >> /etc/bind/reverse.db"
    sudo bash -c "echo '                          8         ; Serial' >> /etc/bind/reverse.db"
    sudo bash -c "echo '                     604800         ; Refresh' >> /etc/bind/reverse.db"
    sudo bash -c "echo '                      86400         ; Retry' >> /etc/bind/reverse.db"
    sudo bash -c "echo '                    2419200         ; Expire' >> /etc/bind/reverse.db"
    sudo bash -c "echo '                     604800 )       ; Negative Cache TTL' >> /etc/bind/reverse.db"
    sudo bash -c "echo '@       IN      NS      $server_name.$domain.' >> /etc/bind/reverse.db"
    sudo bash -c "echo '$(echo $ip_address | awk -F'.' '{print $4}')    IN      PTR     $server_name.$domain.' >> /etc/bind/reverse.db"

    echo "Redemarrage de BIND9..."
    sudo systemctl restart bind9
    echo -e "${GREEN}Configuration DNS terminee pour le domaine $domain, l'adresse IP $ip_address, et le serveur $server_name !${NC}"
}

# Fonction pour configurer le DNS esclave avec BIND9
configure_dns_slave() {
    echo -e "${YELLOW}Configuration de DNS esclave avec BIND9...${NC}"
    sudo apt-get update
    sudo apt-get install -y bind9

    # Utilisation de Zenity pour demander les informations a l'utilisateur dans un formulaire
    result=$(zenity --forms --title="Configuration DNS Esclave" \
                    --text="Entrez les informations pour configurer le DNS esclave" \
                    --add-entry="Domaine (ex: example.com)" \
                    --add-entry="Adresse IP associee au domaine (ex: 192.168.1.50)" \
                    --add-entry="Nom du serveur (ex: ns1)" \
                    --add-entry="Adresse IP du Serveur Maitre (facultatif)")

    # Verification si l'utilisateur a annule ou laisse des champs vides
    if [[ $? -ne 0 ]]; then
        zenity --error --text="L'utilisateur a annule l'entree."
        return
    fi

    # Separation des valeurs saisies dans le formulaire
    domain=$(echo $result | cut -d'|' -f1)
    domain_ip=$(echo $result | cut -d'|' -f2)
    server_name=$(echo $result | cut -d'|' -f3)
    master_ip=$(echo $result | cut -d'|' -f4)

    if [[ -z "$domain" || -z "$domain_ip" || -z "$server_name" ]]; then
        zenity --error --text="Les champs Domaine, Adresse IP et Nom du serveur sont obligatoires."
        return
    fi

    echo "Creation du fichier de configuration pour le serveur esclave..."
    sudo touch /etc/bind/named.conf.local

    # Ajout de la zone esclave dans named.conf.local
    sudo bash -c "echo 'zone \"$domain\" IN {' > /etc/bind/named.conf.local"
    sudo bash -c "echo '    type slave;' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    file \"/var/cache/bind/$domain.db\";' >> /etc/bind/named.conf.local"
    [[ -n "$master_ip" ]] && sudo bash -c "echo '    masters { $master_ip; };' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    allow-transfer { none; };' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '};' >> /etc/bind/named.conf.local"

    # Creation automatique de la zone inverse
    reverse_network=$(echo $domain_ip | awk -F'.' '{print $3"."$2"."$1}')
    sudo bash -c "echo 'zone \"$reverse_network.in-addr.arpa\" IN {' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    type slave;' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    file \"/var/cache/bind/$reverse_network.db\";' >> /etc/bind/named.conf.local"
    [[ -n "$master_ip" ]] && sudo bash -c "echo '    masters { $master_ip; };' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '    allow-transfer { none; };' >> /etc/bind/named.conf.local"
    sudo bash -c "echo '};' >> /etc/bind/named.conf.local"

    echo "Redemarrage de BIND9..."
    sudo systemctl restart bind9
    echo -e "${GREEN}Configuration DNS esclave terminee pour le domaine $domain et l'adresse IP $domain_ip !${NC}"
}


#Ldap configuration 
configure_ldap_client() {
    echo "Préparation de la configuration non interactive de LDAP client..."

    # Exporter la variable DEBIAN_FRONTEND pour éviter les interfaces interactives
    export DEBIAN_FRONTEND=noninteractive

    # Préconfigurer les réponses pour éviter les invites interactives
    echo "Préconfiguration des paquets LDAP..."
    sudo debconf-set-selections <<EOF
ldap-auth-config ldap-auth-config/ldapns/ldap-server string ldap://127.0.0.1
ldap-auth-config ldap-auth-config/ldapns/base-dn string $myDomain
ldap-auth-config ldap-auth-config/bindpw password secret
ldap-auth-config ldap-auth-config/binddn string cn=proxyuser,$myDomain
ldap-auth-config ldap-auth-config/rootbinddn string cn=admin,$myDomain
ldap-auth-config ldap-auth-config/dbrootlogin boolean true
ldap-auth-config ldap-auth-config/purge boolean false
ldap-auth-config ldap-auth-config/move-to-debconf boolean true
EOF

    # Mise à jour des paquets
    sudo apt update -y

    # Reconfiguration silencieuse de ldap-auth-config
    echo "Reconfiguration silencieuse de ldap-auth-config..."
    sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive ldap-auth-config

    # Configuration des fichiers nécessaires
    echo "Configuration de /etc/nsswitch.conf..."
    sudo bash -c 'cat > /etc/nsswitch.conf <<EOL
passwd:         compat systemd ldap
group:          compat systemd ldap
shadow:         compat
gshadow:        files
hosts:          files mdns4_minimal [NOTFOUND=return] dns
networks:       files
protocols:       db files
services:       db files
ethers:         db files
rpc:            db files
netgroup:       nis
EOL'

    echo "Configuration de /etc/pam.d/common-password..."
    sudo bash -c 'cat > /etc/pam.d/common-password <<EOL
password	requisite			pam_pwquality.so retry=3
password	[success=3 default=ignore]	pam_unix.so obscure try_first_pass yescrypt
password	sufficient			pam_sss.so use_authtok
password	[success=1 user_unknown=ignore default=die]	pam_ldap.so use_authtok try_first_pass
password	requisite			pam_deny.so
password	required			pam_permit.so
password	optional	pam_gnome_keyring.so
EOL'

    echo "Configuration de /etc/pam.d/common-session..."
    sudo bash -c 'cat > /etc/pam.d/common-session <<EOL
session	[default=1]			pam_permit.so
session	requisite			pam_deny.so
session	required			pam_permit.so
session optional			pam_umask.so
session	required	pam_unix.so 
session	optional			pam_sss.so 
session	optional			pam_ldap.so 
session	optional	pam_systemd.so 
session optional pam_mkhomedir.so skel=/etc/skel umask=077
EOL'

    sudo systemctl restart nscd
    sudo systemctl enable nscd

    echo "LDAP client configuré avec succès sans interfaces interactives."
}




#configure nginx apache 


configure_nginx_apache() {
    echo "Mise à jour des paquets et installation de Nginx et Apache..."
    sudo apt update -y
    sudo apt install -y nginx apache2 apache2-utils openssl

    # Configuration des répertoires et certificats SSL
    echo "Création des répertoires et génération des certificats SSL..."
    sudo mkdir -p /var/cache/nginx
    sudo chown -R www-data:www-data /var/cache/nginx

    sudo mkdir -p /etc/nginx/ssl
    sudo openssl genrsa -out /etc/nginx/ssl/nginx_mitm.key 2048
    sudo openssl req -new -x509 -key /etc/nginx/ssl/nginx_mitm.key -out /etc/nginx/ssl/nginx_mitm.crt -days 365 -subj "/CN=nginx_mitm"

    sudo mkdir -p /etc/apache2/ssl
    sudo openssl genrsa -out /etc/apache2/ssl/apache2.key 2048
    sudo openssl req -new -x509 -key /etc/apache2/ssl/apache2.key -out /etc/apache2/ssl/apache.crt -days 365 -subj "/CN=apache"

    # Création du fichier htpasswd pour la protection de l'accès
    echo "Création d'un fichier htpasswd pour l'accès sécurisé..."
    sudo htpasswd -bc /etc/nginx/.htpasswd dba password123

    # Sauvegarde de la configuration par défaut de Nginx
    sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak

    # Configuration de Nginx
    echo "Configuration de Nginx..."
    sudo bash -c 'cat > /etc/nginx/sites-available/default' <<EOF
proxy_cache_path /var/cache/nginx/ levels=1:2 keys_zone=cache_zone:10m max_size=1g inactive=60m use_temp_path=off;

server {
    listen 80;
    server_name votre_domaine.com www.votre_domaine.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        add_header X-Proxy-Message "http://\$host;";
    }
}

server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/nginx_mitm.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx_mitm.key;
    server_name _;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        proxy_cache cache_zone;
        proxy_cache_key "\$host\$request_uri";
        proxy_cache_valid 200 15m;
        proxy_cache_valid 404 1m;
        try_files \$uri \$uri/ =404;
        auth_basic "admin area";
        auth_basic_user_file /etc/nginx/.htpasswd;

        add_header X-Cache-Status \$upstream_cache_status;
        proxy_set_header X-MITM-Proxy "NGINX MITM Proxy";
        add_header X-Proxy-Message "https://\$host; Traffic Intercepted and Decrypted by NGINX.";
    }

    location ~* \.(jpg|jpeg|png|gif|css|js|woff|woff2|ttf|svg)\$ {
        root /var/www/html;
        expires 30d;
        add_header Cache-Control "public, max-age=2592000";
    }
}
EOF

    # Configuration d'Apache pour écouter sur les ports 8080 et 8443
    echo "Configuration d'Apache..."
    sudo bash -c 'cat > /etc/apache2/ports.conf' <<EOF
Listen 8080
<IfModule ssl_module>
    Listen 8443
</IfModule>
<IfModule mod_gnutls.c>
    Listen 8443
</IfModule>
EOF

    # Configuration du site Apache
    sudo bash -c 'cat > /etc/apache2/sites-available/000-default.conf' <<EOF
<VirtualHost *:8080>
    RewriteEngine on
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*) https://%{SERVER_NAME}/\$1 [R=301,L]
</VirtualHost>

<VirtualHost *:8443>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/apache.crt
    SSLCertificateKeyFile /etc/apache2/ssl/apache2.key
</VirtualHost>
EOF

    # Activation des modules Apache rewrite et ssl
    echo "Activation des modules Apache..."
    sudo a2enmod rewrite
    sudo a2enmod ssl
    
    # Redémarrage des services Apache et Nginx
    echo "Redémarrage des services Apache et Nginx..."
    sudo systemctl restart apache2
    sudo systemctl restart nginx

    echo "Configuration terminée avec succès."
}

#configure FTP ----------------------------------------------------------------------

configure_FTP() {
    echo "Installation et configuration du serveur FTP en cours..."

    # Installer vsftpd et lftp
    sudo apt update
    sudo apt install -y vsftpd lftp

    # Démarrer et activer le service vsftpd
    sudo systemctl start vsftpd
    sudo systemctl enable vsftpd

    # Sauvegarder la configuration par défaut
    sudo cp /etc/vsftpd.conf /etc/vsftpd.conf_default

    # Créer les utilisateurs et définir leurs mots de passe
    sudo useradd -m -p "$(openssl passwd -1 'test')" gerant
    sudo useradd -m -p "$(openssl passwd -1 'test')" employe

    # Ajouter 'gerant' au groupe 'employe' et ajuster les permissions
    sudo usermod -aG employe gerant
    sudo chmod -R 775 /home/employe
    #autosigne
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem
    # Configurer vsftpd
    sudo bash -c 'cat > /etc/vsftpd.conf << EOF
chroot_local_user=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
allow_writeable_chroot=YES
max_clients=50
max_per_ip=5

pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000

listen=NO
listen_ipv6=YES

anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES

secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
ssl_enable=YES
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
EOF'
	echo "set ssl:verify-certificate no" | sudo tee -a /etc/lftp.conf > /dev/null

    # Créer la liste chroot et ajouter l'utilisateur gerant
    sudo touch /etc/vsftpd.chroot_list
    echo "gerant" | sudo tee -a /etc/vsftpd.chroot_list > /dev/null

    # Redémarrer le service vsftpd
    sudo systemctl restart vsftpd

    echo "Configuration du serveur FTP terminée avec succès."
}
# Fonction pour afficher un menu avec Zenity


#fonction pour configurer LDAP server 



# Functions
configure_ldap_server() {
echo "$systemPassword" | sudo -S bash <<EOF
apt update
apt install apache2 php php-cgi libapache2-mod-php php-mbstring php-common php-pear -y
apt install slapd ldap-utils -y
apt -y install ldap-account-manager
a2enconf php*-cgi

echo "slapd slapd/no_configuration boolean false" | debconf-set-selections
echo "slapd slapd/password1 password $ldapPassword" | debconf-set-selections
echo "slapd slapd/password2 password $ldapPassword" | debconf-set-selections
echo "slapd slapd/domain string $myDomain" | debconf-set-selections
echo "slapd shared/organization string $Organization" | debconf-set-selections

DEBIAN_FRONTEND=noninteractive 
EOF
}

#configure LDAP commands 

#!/bin/bash

# Variables
myLdapDomain="dc=Ehtp,dc=Equipe1"
adminDn="cn=admin,$myLdapDomain"

configure_Ldap_requests() {
    # Créer le fichier LDIF avec les entrées données
    cat > add_content.ldif <<EOF
dn: ou=employees,$myLdapDomain
objectClass: organizationalUnit
ou: employees

dn: ou=managers,$myLdapDomain
objectClass: organizationalUnit
ou: managers

dn: uid=Saad,ou=employees,$myLdapDomain
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: Saad
sn: Ajale
givenName: Saad
cn: Saad Ajale
displayName: Saad Ajale
uidNumber: 10000
gidNumber: 5000
userPassword: {CRYPT}x
gecos: Saad Ajale
loginShell: /bin/bash
homeDirectory: /home/Saad

dn: uid=Bahae,ou=employees,$myLdapDomain
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: Bahaeddine
sn: Aouanet
givenName: Bahaeddine
cn: Bahaeddine Aouanet
displayName: Bahaeddine Aouanet
uidNumber: 10000
gidNumber: 5000
userPassword: {CRYPT}x
gecos: Bahaeddine Aouanet
loginShell: /bin/bash
homeDirectory: /home/Bahaeddine

dn: uid=Lahcen,ou=employees,$myLdapDomain
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: Lahcen
sn: Benhaddou
givenName: Lahcen
cn: Lahcen Benhaddou
displayName: Lahcen Benhaddou
uidNumber: 10000
gidNumber: 5000
userPassword: {CRYPT}x
gecos: Lahcen Benhaddou
loginShell: /bin/bash
homeDirectory: /home/Lahcen

dn: uid=Fatimazahra,ou=employees,$myLdapDomain
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: Fatimazahra
sn: Errazi
givenName: Fatimazahra
cn: Fatimazahra Errazi
displayName: Fatimazahra Errazi
uidNumber: 10000
gidNumber: 5000
userPassword: {CRYPT}x
gecos: Fatimazahra Errazi
loginShell: /bin/bash
homeDirectory: /home/Fatimazahra

dn: uid=Rghioui,ou=managers,$myLdapDomain
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: Rghioui
sn: Rghioui
givenName: Rghioui
cn: Rghioui Rghioui
displayName: Rghioui Rghioui
uidNumber: 10000
gidNumber: 5000
userPassword: {CRYPT}x
gecos: Rghioui Rghioui
loginShell: /bin/bash
homeDirectory: /home/Rghioui
EOF

    echo "Fichier LDIF créé : add_content.ldif"

    # Menu principal avec Zenity
    while true; do
        choice=$(zenity --list --title="Menu LDAP" --column="Option" \
            "Recherche LDAP simple" \
            "Recherche LDAP avec authentification" \
            "Recherche DN uniquement" \
            "Afficher le schéma LDAP" \
            "Créer et ajouter un fichier LDIF" \
            "Changer le mot de passe d'un utilisateur" \
            "Quitter")

        case $choice in
            "Recherche LDAP simple")
                zenity --info --text="Recherche LDAP simple en cours..."
                ldapsearch -H ldapi:/// -x -b "$myLdapDomain"
                ;;
            "Recherche LDAP avec authentification")
                zenity --info --text="Recherche LDAP avec authentification en cours..."
                ldapsearch -H ldapi:/// -x -D "$adminDn" -W -b "$myLdapDomain"
                ;;
            "Recherche DN uniquement")
                zenity --info --text="Recherche des DN uniquement..."
                ldapsearch -x -LLL -b "$myLdapDomain" dn
                ;;
            "Afficher le schéma LDAP")
                zenity --info --text="Affichage du schéma LDAP..."
                ldapsearch -x -H ldap:/// -b "$myLdapDomain" dn
                ;;
            "Créer et ajouter un fichier LDIF")
                if sudo ldapadd -x -D "$adminDn" -W -f "add_content.ldif"; then
                    zenity --info --text="Le fichier LDIF a été ajouté avec succès."
                else
                    zenity --error --text="Échec lors de l'ajout du fichier LDIF."
                fi
                ;;
            "Changer le mot de passe d'un utilisateur")
                userUid=$(zenity --entry --title="Changer le mot de passe" --text="Entrez le UID de l'utilisateur (ex: toto):")
                userDn="uid=$userUid,ou=employees,$myLdapDomain"
                if ldappasswd -x -D "$adminDn" -W -S "$userDn"; then
                    zenity --info --text="Mot de passe modifié avec succès pour $userDn."
                else
                    zenity --error --text="Échec lors du changement du mot de passe."
                fi
                ;;
            "Quitter")
                zenity --info --text="Quitter le programme."
                break
                ;;
            *)
                zenity --error --text="Option invalide, veuillez réessayer."
                ;;
        esac
    done
}




#-------------------------------------SMTP POP IMAPPPPPPPPPPPPPPPPPPPPPP

configure_smtp_pop_imap() {
    # Demander le nom de domaine via Zenity
    domain=$(zenity --entry --title="Configuration SMTP/POP/IMAP" --text="Entrez le nom de votre domaine:")

    # Si l'utilisateur annule ou n'entre rien
    if [ -z "$domain" ]; then
        zenity --error --title="Erreur" --text="Aucun domaine fourni. Annulation."
        return
    fi

    sudo true
    echo "Configuration du serveur localement avec le domaine : $domain"
    sudo bash -c "echo '127.0.0.1   mail.$domain' >> /etc/hosts"

    zenity --info --title="Succès" --text="Le domaine mail.$domain a été ajouté à /etc/hosts."

# Préconfigurer les réponses pour éviter les interfaces interactives de Debconf
echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
echo "postfix postfix/mailname string $mydomain" | sudo debconf-set-selections

# Désactiver les interfaces interactives de Debconf
export DEBIAN_FRONTEND=noninteractive

  echo "Installation des paquets"
  sudo apt update && sudo apt upgrade -y
  sudo apt install postfix dovecot-core dovecot-imapd dovecot-pop3d mailutils -y


cat <<EOL > /etc/postfix/main.cf
# See /usr/share/postfix/main.cf.dist for a commented, more complete version


# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP $mail_name (Ubuntu)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 2 on
# fresh installs.
compatibility_level = 2



# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may

smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache


smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = mail.$mydomain
mydomain = $mydomain
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = $mydomain
mydestination =  mail.$mydomain, localhost.$mydomain, localhost, $mydomain
relayhost = 
home_mailbox = Maildir/
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
EOL

echo "fichiers postfix bien"
sudo systemctl restart postfix



cat <<EOL > /etc/dovecot/conf.d/10-mail.conf
mail_location = maildir:~/Maildir
namespace inbox {
  inbox = yes
}
protocol !indexer-worker {
  # If folder vsize calculation requires opening more than this many mails from
  # disk (i.e. mail sizes aren't in cache already), return failure and finish
  # the calculation via indexer process. Disabled by default. This setting must
  # be 0 for indexer-worker processes.
  #mail_vsize_bg_after_count = 0
}
EOL

cat <<EOL >  /etc/dovecot/conf.d/10-auth.conf

auth_mechanisms = plain
#!include auth-deny.conf.ext
#!include auth-master.conf.ext

!include auth-system.conf.ext
#!include auth-sql.conf.ext
#!include auth-ldap.conf.ext
#!include auth-passwdfile.conf.ext
#!include auth-checkpassword.conf.ext
#!include auth-vpopmail.conf.ext
#!include auth-static.conf.ext
disable_plaintext_auth = no

EOL

cat <<EOL > /etc/dovecot/conf.d/10-master.conf

#default_process_limit = 100
#default_client_limit = 1000

# Default VSZ (virtual memory size) limit for service processes. This is mainly
# intended to catch and kill processes that leak memory before they eat up
# everything.
#default_vsz_limit = 256M

# Login user is internally used by login processes. This is the most untrusted
# user in Dovecot system. It shouldn't have access to anything at all.
#default_login_user = dovenull

# Internal user is used by unprivileged processes. It should be separate from
# login user, so that login processes can't disturb other processes.
#default_internal_user = dovecot

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }

  # Number of connections to handle before starting a new process. Typically
  # the only useful values are 0 (unlimited) or 1. 1 is more secure, but 0
  # is faster. <doc/wiki/LoginProcess.txt>
  #service_count = 1

  # Number of processes to always keep waiting for more connections.
  #process_min_avail = 0

  # If you set service_count=0, you probably need to grow this.
  #vsz_limit = $default_vsz_limit
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service submission-login {
  inet_listener submission {
    #port = 587
  }
}

service lmtp {
  unix_listener lmtp {
    #mode = 0666
  }

  # Create inet listener only if you can't use the above UNIX socket
  #inet_listener lmtp {
    # Avoid making LMTP visible for the entire internet
    #address =
    #port = 
  #}
}

service imap {
  # Most of the memory goes to mmap()ing files. You may need to increase this
  # limit if you have huge mailboxes.
  #vsz_limit = $default_vsz_limit

  # Max. number of IMAP processes (connections)
  #process_limit = 1024
}

service pop3 {
  # Max. number of POP3 processes (connections)
  #process_limit = 1024
}

service submission {
  # Max. number of SMTP Submission processes (connections)
  #process_limit = 1024
}

service auth {
  # auth_socket_path points to this userdb socket by default. It's typically
  # used by dovecot-lda, doveadm, possibly imap process, etc. Users that have
  # full permissions to this socket are able to get a list of all usernames and
  # get the results of everyone's userdb lookups.
  #
  # The default 0666 mode allows anyone to connect to the socket, but the
  # userdb lookups will succeed only if the userdb returns an "uid" field that
  # matches the caller process's UID. Also if caller's uid or gid matches the
  # socket's uid or gid the lookup succeeds. Anything else causes a failure.
  #
  # To give the caller full permissions to lookup all users, set the mode to
  # something else than 0666 and Dovecot lets the kernel enforce the
  # permissions (e.g. 0777 allows everyone full permissions).
  unix_listener auth-userdb {
    #mode = 0666
    #user = 
    #group = 
  }

  # Postfix smtp-auth
  #unix_listener /var/spool/postfix/private/auth {
  #  mode = 0666
  #}

  # Auth process is run as this user.
  #user = $default_internal_user
}

service auth-worker {
  # Auth worker process is run as root by default, so that it can access
  # /etc/shadow. If this isn't necessary, the user should be changed to
  # $default_internal_user.
  #user = root
}

service dict {
  # If dict proxy is used, mail processes should have access to its socket.
  # For example: mode=0660, group=vmail and global mail_access_groups=vmail
  unix_listener dict {
    #mode = 0600
    #user = 
    #group = 
  }
}
EOL

cat <<EOL > /etc/dovecot/conf.d/10-ssl.conf
ssl = required
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_client_ca_dir = /etc/ssl/certs
ssl_dh = </usr/share/dovecot/dh.pem
EOL

echo "j ai configure tous les fichiers"

sudo systemctl restart dovecot

}


#---------------------------------------------------------------AACCEDER FTP SERVER ------------------------------------
Acceder_FTP_SERVER() {
    # Paramètres LDAP
    LDAP_SERVER="ldap://localhost"
    LDAP_BIND_DN="cn=admin,dc=Ehtp,dc=Equipe1"
    LDAP_PASSWORD="test"
    LDAP_BASE_DN="dc=Ehtp,dc=Equipe1"

    # Saisie de l'utilisateur avec Zenity
    USER=$(zenity --entry --title="Accéder au FTP Server" \
        --text="Veuillez entrer l'UID de l'utilisateur :" \
        --entry-text "")

    # Vérifier si l'utilisateur a annulé ou n'a pas saisi d'UID
    if [ -z "$USER" ]; then
        zenity --error --title="Erreur" --text="Aucun utilisateur fourni. Opération annulée."
        exit 1
    fi

    # Requête LDAP pour trouver le DN de l'utilisateur
    result=$(ldapsearch -x -LLL -H "$LDAP_SERVER" \
        -D "$LDAP_BIND_DN" -w "$LDAP_PASSWORD" \
        -b "$LDAP_BASE_DN" "(uid=$USER)" | grep "^dn:")

    # Vérifie si le résultat contient quelque chose
    if [[ -n $result ]]; then
        # Extraction de la valeur après "ou="
        extracted_group=$(echo "$result" | sed -n 's/.*ou=\([^,]*\).*/\1/p')

        # Mappage du groupe
        if [ "$extracted_group" == "managers" ]; then
            lftp -u gerant,test ftp://127.0.0.1
        elif [ "$extracted_group" == "employees" ]; then
            lftp -u employe,test ftp://127.0.0.1
        else
            zenity --error --title="Erreur" --text="Groupe inconnu pour l'utilisateur : $USER"
            exit 1
        fi
    else
        zenity --error --title="Erreur" --text="Aucun utilisateur trouvé pour UID : $USER"
        exit 1
    fi
}
# Menu principal
show_menu() {
    choice=$(zenity --list --radiolist --title="Menu de Configuration" \
                    --text="Choisissez une option:" \
                    --column="Selection" --column="Option" \
                    TRUE "Configurer DNS" \
                    FALSE "Configurer DHCP" \
                    FALSE "Configurer Apache2/Nginx/Proxy" \
                    FALSE "Configurer SMTP/POP/IMAP" \
                    FALSE "Configurer FTP" \
                    FALSE "Configurer LDAP")

    # Si "Annuler" ou aucune sélection
    if [ -z "$choice" ]; then
        echo "Retour au menu principal."
        return
    fi

    case $choice in
        "Configurer DNS")
            dns_choice=$(zenity --list --radiolist --title="Choix du type de DNS" \
                                --text="Choisissez le type de serveur DNS à configurer:" \
                                --column="Selection" --column="Option" \
                                TRUE "Configurer DNS Principal" \
                                FALSE "Configurer DNS Esclave")
            if [ -z "$dns_choice" ]; then
                echo "Retour au menu principal."
                return
            fi
            case $dns_choice in
                "Configurer DNS Principal")
                    configure_dns_master
                    ;;
                "Configurer DNS Esclave")
                    configure_dns_slave
                    ;;
                *)
                    echo "Option DNS invalide."
                    ;;
            esac
            ;;
        "Configurer DHCP")
            dhcp_choice=$(zenity --list --radiolist --title="Configuration DHCP" \
                                 --text="Choisissez une option DHCP:" \
                                 --column="Selection" --column="Option" \
                                 TRUE "Configurer Serveur DHCP" )
            if [ -z "$dhcp_choice" ]; then
                echo "Retour au menu principal."
                return
            fi
            case $dhcp_choice in
                "Configurer Serveur DHCP")
                    configure_dhcp
                    ;;
                *)
                    echo "Option DHCP invalide."
                    ;;
            esac
            ;;
        "Configurer Apache2/Nginx/Proxy")
            apache_choice=$(zenity --list --radiolist --title="Configuration Apache2/Nginx/Proxy" \
                                   --text="Choisissez une option Apache2/Nginx/Proxy à configurer:" \
                                   --column="Selection" --column="Option" \
                                   TRUE "Configurer Nginx Apache2 Proxy" )
            if [ -z "$apache_choice" ]; then
                echo "Retour au menu principal."
                return
            fi
            case $apache_choice in
                "Configurer Nginx Apache2 Proxy")
                    configure_nginx_apache
                    ;;

                *)
                    echo "Option Apache2/Nginx/Proxy invalide."
                    ;;
            esac
            ;;
        "Configurer SMTP/POP/IMAP")
            smtp_choice=$(zenity --list --radiolist --title="Configuration SMTP/POP/IMAP" \
                                 --text="Choisissez une option SMTP/POP/IMAP:" \
                                 --column="Selection" --column="Option" \
                                 TRUE "Configurer SMTP POP IMAP")
            if [ -z "$smtp_choice" ]; then
                echo "Retour au menu principal."
                return
            fi
            case $smtp_choice in
                "Configurer SMTP POP IMAP")
                    configure_smtp_pop_imap
                    ;;
                *)
                    echo "Option SMTP/POP/IMAP invalide."
                    ;;
            esac
            ;;
        "Configurer FTP")
            ftp_choice=$(zenity --list --radiolist --title="Configuration FTP" \
                                --text="Choisissez une option FTP:" \
                                --column="Selection" --column="Option" \
                                TRUE "Configurer Serveur FTP" \
                                FALSE "Acceder Serveur FTP")
            if [ -z "$ftp_choice" ]; then
                echo "Retour au menu principal."
                return
            fi
            case $ftp_choice in
                "Configurer Serveur FTP")
                    configure_FTP
                    ;;
                "Acceder Serveur FTP")
                    Acceder_FTP_SERVER
                    ;;
                
            esac
            ;;
        "Configurer LDAP")
            ldap_choice=$(zenity --list --radiolist --title="Configuration LDAP" \
                                --text="Choisissez une option LDAP à configurer:" \
                                --column="Selection" --column="Option" \
                                TRUE "Configurer Serveur LDAP" \
                                FALSE "Appliquer Requêtes LDAP" \
                                FALSE "Configurer Client LDAP")
            if [ -z "$ldap_choice" ]; then
                echo "Retour au menu principal."
                return
            fi
            case $ldap_choice in
                "Configurer Serveur LDAP")
                    configure_ldap_server
                    ;;
                "Appliquer Requêtes LDAP")
                    configure_Ldap_requests
                    ;;
                "Configurer Client LDAP")
                    configure_ldap_client
                    ;;
                *)
                    echo "Option LDAP invalide."
                    ;;
            esac
            ;;
        "Quitter")
            echo "Sortie..."
            exit 0
            ;;
        *)
            exit 0
            ;;
    esac
}

# Exécution du menu en boucle
while true; do
    show_menu
done

#!/bin/bash -e
clear
# set -x
##color
RED='\033[0;31m'
GREEN='\e[32m'
YELLOW='\033[1;33m'
BLUE='\033[1;32m'
NC='\033[0m'

##...............BANNER...............
function banner(){
    echo -e "XXX\n$1\n$2\nXXX"
}
 
##...............CHECK ROOT USER...............

check_root(){
    if [[ $(id -u) != 0 ]];
    then 
        echo -e "${RED}[ FAILED ]${NC} Root Permission Requirement Failed"
        exit;
    fi 
}

createlog(){

    NOW=$(date +"%m-%d-%Y-%T")
    mkdir -p /klab/
    mkdir -p /klab/samba
    mkdir -p /klab/samba/log
    LOG="/klab/samba/log/clientlog-$NOW"

    rm -rf $LOG
}

function sethostname(){

    samba_hostname=$(TERM=ansi whiptail --clear --title "[ Hostname Selection ]" --backtitle "Samba Active Directory Domain Controller" \
    --nocancel --ok-button Submit --inputbox \
    "\nPlease enter a suitable new hostname for the active directory server.\n\nExample:  adlab\n" 10 80 3>&1 1>&2 2>&3)
    sudo hostnamectl set-hostname $samba_hostname
    HOSTNAME=$samba_hostname

}

function sambainput(){

    samba_realm=$(TERM=ansi whiptail --clear --title "[ Realm Selection ]"  --backtitle "Samba Active Directory Domain Controller" \
    --nocancel --ok-button Submit --inputbox \
    "\nPlease enter a realm name for the active directory server.\n\nExample:  KOOMPILAB.ORG\n" 10 80 3>&1 1>&2 2>&3)
    
    secondlvl_domain=$(echo $samba_realm |awk -F'.' '{printf $NF}')
    samba_domain=${samba_realm//".$secondlvl_domain"}
    samba_realm=${samba_realm^^}
    samba_domain=${samba_domain^^}


    while true;
    do
        samba_password=$(TERM=ansi whiptail --clear --title "[ Administrator Password ]" --backtitle "Samba Active Directory Domain Controller" \
        --nocancel --ok-button Submit --passwordbox \
        "\nPlease enter your password for administrator user of active directory server\nNote:  IT MUST BE \
NO LESS THAN 8 CHARACTERS and AT LEAST AN UPPER ALPHABET and A NUMBER" 10 80  3>&1 1>&2 2>&3)

        samba_password_again=$(TERM=ansi whiptail --clear --title "[ Administrator Password ]"  --backtitle "Samba Active Directory Domain Controller" \
        --nocancel --ok-button Submit  --passwordbox \
        "\nPlease enter your password for administrator user of active directory server again" 10 80  3>&1 1>&2 2>&3)

        if  [[ "$samba_password" != "$samba_password_again" ]];
        then
            TERM=ansi whiptail --clear --backtitle "Samba Active Directory Domain Controller" --title \
            "[ Administrator Password ]" --msgbox "Your password does match. Please retype it again" 10 80

        elif [[ "${#samba_password}" < 8 ]];
        then
                TERM=ansi whiptail --clear --backtitle "Samba Active Directory Domain Controller" --title \
                "[ Administrator Password ]" --msgbox "Your password does not meet the length requirement. \
    IT MUST BE NO LESS THAN 8 CHARACTERS and AT LEAST AN UPPER ALPHABET and A NUMBER" 10 80
        else
                break
        fi
    done


    while true;
    do
        samba_ip=$(TERM=ansi whiptail --clear --backtitle "Samba Active Directory Domain Controller"  --title "[ IP for Domain ]" \
        --nocancel --ok-button Submit  --inputbox \
        "\nPlease enter an IP for your new active directory server\nExample:  172.16.1.1\n" 8 80 3>&1 1>&2 2>&3)
        if [[ $samba_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];
        then
            break
        else
            TERM=ansi whiptail --clear --backtitle "Samba Active Directory Domain Controller" --title "[ IP for Domain ]" \
            --msgbox "Your IP isn't valid. A valid IP should looks like XXX.XXX.XXX.XXX" 10 80
        fi
    done
}

function pathinput(){

    NETLOGONPATH=$(TERM=ansi whiptail --clear --title "[ NETLOGON Selection ]"  --backtitle "Samba Active Directory Domain Controller" \
    --nocancel --ok-button Submit  --inputbox \
    "\nPlease enter a path for Samba User Netlogon for the active directory.\n\nDefault:  /klab/samba/netlogon\n" 10 100 3>&1 1>&2 2>&3)

    HOMEPATH=$(TERM=ansi whiptail --clear --title "[ HOME Selection ]" --backtitle "Samba Active Directory Domain Controller" \
    --nocancel --ok-button Submit  --inputbox \
    "\nPlease enter a path for Samba User Home for the active directory.\n\nDefault:  /klab/samba/home\n" 10 100 3>&1 1>&2 2>&3)

    PROFILESPATH=$(TERM=ansi whiptail --clear --title "[ HOME Selection ]" --backtitle "Samba Active Directory Domain Controller" \
    --nocancel --ok-button Submit  --inputbox \
    "\nPlease enter a path for Samba User Profiles for the active directory.\n\nDefault:  /klab/samba/profiles\n" 10 100 3>&1 1>&2 2>&3)

    if [ -z "$NETLOGONPATH" ]
    then
        NETLOGONPATH='/klab/samba/netlogon'
    fi
    if [ -z "$HOMEPATH" ]
    then
        HOMEPATH='/klab/samba/home'
    fi
    if [ -z "$PROFILESFATH" ]
    then
        PROFILESPATH='/klab/samba/profiles'
    fi

}

function inputcheck(){

    ##cut ip address on index
    ip1=$(echo ${samba_ip} | awk -F'.' '{print $1}')
    ip2=$(echo ${samba_ip} | awk -F'.' '{print $2}')
    ip3=$(echo ${samba_ip} | awk -F'.' '{print $3}')
    ip4=$(echo ${samba_ip} | awk -F'.' '{print $4}')

    while true;
    do
        if (TERM=ansi whiptail --clear --backtitle "Samba Active Directory Domain Controller" --title "[ AD Information ]" \
        --yesno "Your Samba Active Directory Domain Controller Information is\n
    Realm :    ${samba_realm}
    Domain:    ${samba_domain}
    Role  :    DC
    DNS   :    BIND9_DLZ
    IP    :    ${samba_ip}" 15 100);
        then
            if (TERM=ansi whiptail --clear --backtitle "Samba Active Directory Domain Controller" --title "[ DNS Information ]" \
            --yesno "Your Samba Active Directory Domain Controller DNS Information is\n
    Hostname :    $HOSTNAME
    Realm    :    ${samba_realm,,} 
    IP       :    $ip3.$ip2.$ip1.in-addr.arpa
    PTR      :    $ip4
    Zone     :    $HOSTNAME.${samba_realm,,} $ip3.$ip2.$ip1.in-addr.arpa" 15 100);
            then
                break
            else
                sethostname
                sambainput
            fi
        sambainput
        fi
    done

    while true;
    do
        if (TERM=ansi whiptail --clear --backtitle "Samba Active Directory Domain Controller" --title "[ Path Information ]" \
        --yesno "Your Samba Active Directory Domain Controller Path Information is\n
    Netlogon    :    ${NETLOGONPATH}
    Home        :    ${HOMEPATH}
    Profiles    :    ${PROFILESPATH}" 15 100);
        then
            break
        else
            pathinput
        fi
    done
    
}

##...............INSTALL PACKAGE BASE...............

function install_package_base(){

    progress=6

    for PKG in $(cat $(pwd)/package_x86_64)
    do
        progress=$(echo $(( $progress+2 )))
        banner "$progress" "Installing package $PKG..."

        if [[ -n "$(pacman -Qs ${PKG})" ]];
        then 
            echo -e "${GREEN}[ Found ]${NC} Package:${BLUE} ${PKG} ${NC}Installed." >> $LOG
        else 
            echo -e "${GREEN}Installing ${PKG} ${NC}" >> $LOG
            sudo pacman -S ${PKG} --noconfirm 2>/dev/null >> $LOG
            echo -e "${GREEN}[ OK ]${NC} Package:${BLUE} ${PKG} ${NC}Installed successfull." >> $LOG
        fi
    done

    cp service/samba.service /usr/lib/systemd/system/
}

##...............NTP SERVER FUNCTION SETUP...............
NTP_FILE=(/etc/ntp.conf)

function ntp(){

    if [[ -f "${NTP_FILE}" ]];
    then 
        if [[ -f /etc/ntp.conf.backup ]];
        then 
            echo -e "${GREEN}[ OK ]${NC} ntp config backup"
        else 
            echo -e "${GREEN}[ Check ]${NC} check ntp config backup"
            sudo cp ${NTP_FILE} /etc/ntp.conf.backup 
        fi
    fi

    sudo cp $(pwd)/ntp/ntp.conf /etc/ntp.conf
    echo -e "${GREEN}[ OK ]${NC} Configure ntp.conf"

    ##permission
    sudo install -d /var/lib/samba/ntp_signd
    echo -e "${GREEN}[ OK ]${NC} Install ntp_signd"

    sudo chown root:ntp /var/lib/samba/ntp_signd
    sudo chmod 0750 /var/lib/samba/ntp_signd
    echo -e "${GREEN}[ OK ]${NC} Setup ownership and permission"

    ##enable service
    sudo systemctl enable ntpd.service
    sudo systemctl start ntpd.service
    echo -e "${GREEN}[ OK ]${NC} Starting service"
    echo -e "${GREEN}[ OK ] Configure NTP successful ${NC}"
}

##..................BIND SERVER FUNCTION SETUP...............

function bind(){

    BIND_FILE=/etc/named.conf

    network="$ip1.$ip2.$ip3.0"

    if [[ -f ${BIND_FILE}.backup ]];
    then
        echo -e "${GREEN}[ OK ]${NC} bind config backup"
    else
        sudo cp /etc/named.conf /etc/named.conf.backup
        echo -e "${GREEN}[ Check ]${NC} check bind config backup"
    fi

    sudo cp $(pwd)/bind/empty0.zone /var/named/
    sudo cp $(pwd)/bind/root.hint /var/named/
    sudo cp $(pwd)/bind/named.conf /etc/
    grep -rli IPADDRESS /etc/named.conf | xargs -i@ sed -i s+IPADDRESS+${network}+g @

    sudo touch /var/lib/samba/private/dns.keytab
    echo -e "${GREEN}[ OK ]${NC} Configure zone"

    sudo chgrp named /var/lib/samba/private/dns.keytab
    sudo chmod g+r /var/lib/samba/private/dns.keytab
    echo -e "${GREEN}[ OK ]${NC} Set owner and permission on dns.keytab"

    sudo touch /var/log/named.log
    echo -e "${GREEN}[ OK ]${NC} Creating named.log"

    sudo chown root:named /var/log/named.log
    sudo  chmod 664 /var/log/named.log
    echo -e "${GREEN}[ OK ]${NC} Set owner and permission on name.log"

    sudo cp $(pwd)/bind/empty0.zone /var/named/empty0.zone
    echo -e "${GREEN}[ OK ]${NC} Coping empty.zone"

    sudo chown root:named /var/named/empty0.zone
    echo -e "${GREEN}[ OK ]${NC} Set permission on empty0.zone"

        
    echo -e '#!/bin/bash\nmkdir -p /var/lib/samba/private/dns\nchmod 770 -R /var/lib/samba/private/dns' \
    >  /usr/bin/namedhelper.sh

    echo -e "${GREEN}[ OK ]${NC} Created Named Helper Service"

    chmod +x /usr/bin/namedhelper.sh
    cp service/namedhelper.service /usr/lib/systemd/system/
    systemctl enable namedhelper.service
    systemctl start namedhelper.service

    sudo systemctl enable named
    sudo systemctl start named
    echo -e "${GREEN}[ OK ]${NC} Start service"

    echo -e "${GREEN}[ OK ] Configure BIND successful. ${NC}"
}

#..................SAMBA ACTIVE DIRECTORY FUNCTION................
function samba(){

    sudo systemctl disable samba
    sudo systemctl stop samba
    echo -e "${GREEN}[ OK ]${NC} Disable and stop service"

    sudo rm -rf /etc/samba/smb.conf &&
    echo -e "${GREEN}[ OK ]${NC} Delete file config smb.conf"

    USERNAME=$(id -u -n)

    sudo samba-tool domain provision --server-role=dc --use-rfc2307 --dns-backend=BIND9_DLZ \
    --realm=$samba_realm --domain=$samba_domain --adminpass=$samba_password

    if [[ -f /etc/samba/smb.conf ]];
    then
        sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.backup
    fi 
    
    SMB=/etc/samba/smb.conf
    sudo chown -R $USERNAME:users $SMB
    echo -e "# Global parameters" > $SMB
    echo -e "[global]" >> $SMB
    echo -e "\tnetbios name = $HOSTNAME" >> $SMB
    echo -e "\trealm = ${samba_realm}" >> $SMB
    echo -e "\tworkgroup = ${samba_domain}" >> $SMB
    echo "  + Configure path..."

    echo -e "${GREEN}[ OK ]${NC} Configuring smb.conf..."

    #create path directory
    sudo mkdir -p $NETLOGONPATH
    sudo mkdir -p $HOMEPATH
    sudo mkdir -p $PROFILESPATH
    echo -e "${GREEN}[ OK ]${NC} Create directory"

    #permission
    sudo chown -R root:users $NETLOGONPATH
    sudo chown -R root:users $HOMEPATH
    sudo chown -R root:users $PROFILESPATH
    sudo chmod 0777 $NETLOGONPATH
    sudo chmod 0777 $HOMEPATH
    sudo chmod 0777 $PROFILESPATH
    echo -e "${GREEN}[ OK ]${NC} Set permisson"

    grep -rli SMBNE $(pwd)/samba/smb | xargs -i@ sed -i s+SMBNE+$NETLOGONPATH+g @
    grep -rli SMBHO $(pwd)/samba/smb | xargs -i@ sed -i s+SMBHO+"$HOMEPATH/%S"+g @
    grep -rli SMPRO $(pwd)/samba/smb | xargs -i@ sed -i s+SMPRO+$PROFILESPATH+g @
    cat $(pwd)/samba/smb >> $SMB
    sudo chown -R root:root $SMB
    echo -e "${GREEN}[ OK ]${NC} Replace name"

    SAMBALDB_FILE=(/etc/profile.d/sambaldb.sh)
    sudo touch ${SAMBALDB_FILE}
    sudo chown -R ${USERNAME}:users ${SAMBALDB_FILE}
    echo -e "${GREEN}[ OK ]${NC} Creat sambaldb.sh to set LDB_MODULES_PATH"

    echo 'export LDB_MODULES_PATH="${LDB_MODULES_PATH}:/usr/lib/samba/ldb"' > ${SAMBALDB_FILE}

    sudo chown -R root:root ${SAMBALDB_FILE}
    sudo sudo chmod 0755 /etc/profile.d/sambaldb.sh
    echo -e "${GREEN}[ OK ]${NC} set permission"

    
    /etc/profile.d/sambaldb.sh
    echo -e "${GREEN}[ OK ]${NC} /etc/profile.d/sambaldb.sh"
    
    sudo systemctl enable samba
    sudo systemctl start samba
    echo -e "${GREEN}[ OK ]${NC} Enable and Start service"

    echo -e "${GREEN}[ OK ] Configure SAMBA successful. ${NC}"
}

##...............SETUP KERBEROS SERVER..........................
function kerberos(){

    sudo cp krb5/krb5.conf /etc/krb5.conf
    grep -rli SAMBAREALM /etc/krb5.conf | xargs -i@ sed -i s+SAMBAREALM+${samba_realm}+g @
    echo -e "${GREEN}[ OK ]${NC} Copy krb5.conf"
    echo -e "${GREEN}[ OK ]${NC} Configure KERBEROS successful. ${NC}"
}

##................SETUP RESOLVE..................
function resolvs(){

    RESOLVCONF_FILE=/etc/resolvconf.conf
    RESOLV_FILE=/etc/resolv.conf
    
    cp resolvconf/resolvconf.conf /etc/
    grep -rli SEARCHDOMAIN /etc/resolvconf.conf | xargs -i@ sed -i s+SEARCHDOMAIN+${samba_realm,,}+g @    
    echo -e "${GREEN}[ OK ]${NC} Configure Resolveconf"

    echo "search ${samba_realm,,}" > ${RESOLV_FILE}
    echo "nameserver 127.0.0.1" >> ${RESOLV_FILE}
    echo "nameserver 8.8.8.8" >> ${RESOLV_FILE}
    echo "nameserver 8.8.4.4" >> ${RESOLV_FILE}
    echo -e "${GREEN}[ OK ]${NC} Configure Resolve"


    echo -e "[main]\ndns=none\nmain.systemd-resolved=false" > /etc/NetworkManager/conf.d/dns.conf
    resolvconf -u
    echo -e "${GREEN}[ OK ]${NC} Restrict NetworkManager from touching resolv.conf"

    echo -e "${GREEN}[ OK ]${NC} Configure RESOLVE successful. $NC"
}

##................SETUP HOST......................
function hosts(){

    if [[ -f "/etc/hosts.backup" ]]; then
        echo -e "${GREEN}[ OK ]${NC} Hosts backup"
    else
        sudo cp /etc/hosts /etc/hosts.backup
        echo -e "${GREEN}[ Check ]${NC} Check hosts backup"
    fi

    echo "${samba_ip}     ${samba_realm,,}" >> /etc/hosts
    echo -e "${GREEN}[ OK ]${NC} Configure hosts"
}

#..................SET UP DNS BACKEND WITH SAMBA.................
function dnsbackup(){

    systemctl restart named.service
    echo -e "${GREEN}[ OK ]${NC} Restart named service" >> $LOG
    echo "$samba_password" | sudo samba-tool dns zonecreate ${HOSTNAME}.${samba_realm,,} $ip3.$ip2.$ip1.in-addr.arpa -U Administrator
    echo "$samba_password" | sudo samba-tool dns add ${HOSTNAME}.${samba_realm,,} $ip3.$ip2.$ip1.in-addr.arpa $ip4 PTR ${HOSTNAME}.${samba_realm,,} -U Administrator
    sudo host -t PTR ${samba_ip} >> $LOG
    echo -e "${GREEN}[ OK ]${NC} Create DNS backend" >> $LOG
    
}

##....................SETUP NSSWITCH............................
function nsswitch(){

    sudo cp $(pwd)/nsswitch/nsswitch.conf /etc/nsswitch.conf
    echo -e "${GREEN}[ OK ]${NC} Configuring nsswithch"
    echo -e "${GREEN} Configure Nsswitch successful. $NC"
}

##...................TESTING INSTALLATION..........................
function testinstall(){


    banner "90" "Attempt to Start Samba Services"
    sudo systemctl restart samba &>> $LOG
    sudo systemctl enable named &>> $LOG
    sudo systemctl start named &>> $LOG

    echo -e "${GREEN}[ OK ]${NC} Restarting service samba and ntp"  >> $LOG

    echo "  + host -t SRV _ldap._tcp.${samba_realm,,}." >> $LOG
    echo "  + host -t SRV _kerberos._udp.${samba_realm,,}." >> $LOG
    echo "  + host -t A ${samba_realm,,}." >> $LOG

    banner "95" "Attempt to Invoke DNS Registry"

    HOST1=$(host -t SRV _ldap._tcp.${samba_realm,,}.)
    HOST2=$(host -t SRV _kerberos._udp.${samba_realm,,}.)
    HOST3=$(host -t A ${samba_realm,,}.)

    echo -e "Receive output\n$HOST1\n$HOST2\n$HOST3" >> $LOG

    echo -e "$samba_password" | sudo smbclient //localhost/netlogon -U Administrator -c 'ls' &>> $LOG
    echo -e "${GREEN}[ OK ]${NC} NT authentication"  >> $LOG

    sudo systemctl restart samba ntpd named &>> $LOG 
    echo -e "${GREEN}[ OK ]${NC} Restart service" >> $LOG

    sudo samba-tool user setexpiry Administrator --noexpiry &>> $LOG
    echo -e "${GREEN}[ OK ]${NC} Disable Administrator Expriy" >> $LOG

    echo -e "$samba_password" | kinit administrator@${samba_realm} &>> $LOG
    echo -e "${GREEN}[ OK ]${NC} Kerberos authentication" >> $LOG
    echo -e "${GREEN}[ OK ] Test successful. $NC" >> $LOG
}

#.................USER AND GROUP MANAGEMENT............................
function user_management(){

    sudo samba-tool group add network --gid-number=90 --nis-domain=${samba_realm,,}
    sudo samba-tool group add video --gid-number=986 --nis-domain=${samba_realm,,}
    sudo samba-tool group add storage --gid-number=988 --nis-domain=${samba_realm,,}
    sudo samba-tool group add lp --gid-number=991 --nis-domain=${samba_realm,,}
    sudo samba-tool group add audio --gid-number=995 --nis-domain=${samba_realm,,}
    sudo samba-tool group add wheel --gid-number=998 --nis-domain=${samba_realm,,}
    sudo samba-tool group add power --gid-number=98 --nis-domain=${samba_realm,,}
    echo -e "${GREEN}[ OK ]${NC} Creating group"

    sudo samba-tool domain passwordsettings set --complexity=off
    echo -e "${GREEN}[ OK ]${NC} Password complexity: off"

    echo -e "${GREEN}[ OK ] Configure User management successful. $NC"
    echo -e "${GREEN}[ OK ] Configure AD successful.${NC}"

}
##....................SETUP DHCP SERVER................
echo 

function dhcp(){
    d='"'
    echo "option domain-name $d$DHCP_DOMAIN$d; "> $DHCP_FILE
    echo "option domain-name-servers $DHCP_DOMAIN;" >> $DHCP_FILE
    echo "subnet $DHCP_NETWORK netmask $DHCP_NETMASK {" >> $DHCP_FILE
    echo "option routers $DHCP_ROUTER;" >> $DHCP_FILE
    echo "option subnet-mask $DHCP_NETMASK;" >> $DHCP_FILE
    echo "range dynamic-bootp $DHCP_REANGES;}" >> $DHCP_FILE
    #permission
    sudo chown -R root:root /etc/dhcpd.conf
    sudo chmod 644 /etc/dhcpd.conf
    #start service
    sudo systemctl enable dhcpd4
    sudo systemctl start dhcpd4
    echo "successful"
}
function reads(){

    #read items
    read -p "$(echo -e "$RED Network $NC: ")"    DHCP_NETWORK
    read -p "$(echo -e "$RED Netmask $NC: ")"    DHCP_NETMASK
    read -p "$(echo -e "$RED Routers $NC: ")"    DHCP_ROUTER
    read -p "$(echo -e "$RED Ranges $NC : ")"    DHCP_REANGES
    read -p "$(echo -e "$RED Domain $NC : ")"    DHCP_DOMAIN

    #show items
    echo -e "..........YOUR INPUT..........."
    echo -e "$RED Network $NC: $DHCP_NETWORK"
    echo -e "$RED Netmask $NC: $DHCP_NETMASK"
    echo -e "$RED Routers $NC: $DHCP_ROUTER"
    echo -e "$RED Ranges $NC: $DHCP_REANGES"
    echo -e "$RED Domain $NC: $DHCP_DOMAIN"
    read -p "continue or again [C/A]:" ca
    CA=$(echo "$ca" | tr '[:upper:]' '[:lower:]')
    if [[ $CA == c ]];then
        dhcp #call dhcp
    else
        reads #call reads
    fi
}
DHCP_FILE=(/etc/dhcpd.conf)
USERNAME=$(id -n -u)
function maindhcp(){
read -p "$(echo -e $YELLOW"Do you need setup $RED DHCP $NC $YELLOW Server:[Yes/No]:"$NC)" YN
D=$(echo "$YN" | tr '[:upper:]' '[:lower:]')
if [[ $D == yes || $D == y || $D == ye ]];then
    if [[ -f $DHCP_FILE ]];then #check dhcp file created or not
        if [[ -f /etc/dhcpd.conf.backup ]];then #check dhcp backup create or not
            sudo chown -R $USERNAME:$USERNAME $DHCP_FILE
            sudo chmod 744 $DHCP_FILE
            reads #call reads
        else 
            sudo mv /etc/dhcpd.conf /etc/dhcpd.conf.backup
            sudo touch /etc/dhcpd.conf
            sudo chown -R $USERNAME:$USERNAME /etc/dhcpd.conf
            sudo chmod 744 /etc/dhcpd.conf
            reads #call reads
        fi #end of check dhcp backup file
    else 
        sudo touch /etc/dhcpd.conf
        maindhcp #call maindhcp
    fi # end of check dhcp file
fi
}
# maindhcp

#.....................SETUP FTP SERVER...................
function ftp(){
read -p "$(echo -e $YELLOW"Do you need setup $RED FTP $NC $YELLOW Server:[Yes/No]:"$NC)" YN
F=$(echo "$YN" | tr '[:upper:]' '[:lower:]')
if [[ $F == yes || $F == y || $F == ye ]];then
    #service
    sudo systemctl enable docker 
    sudo systemctl start docker
    ftpread(){
        read -p "$(echo -e "$RED Directory Path:$NC")" FTP_DIRPATH
        read -p "$(echo -e "$RED IP Address:$NC")" FTP_IPADDRESS
        read -p "$(echo -e "$RED Images name:$NC")" FTP_IMAGENAME
        read -p "$(echo -e "$RED port:$NC")" FTP_PORT
        read -p "$(echo -e "$RED Username:$NC")" FTP_NAME
        read -s -p "$(echo -e "$RED Password:$NC")" FTP_PASSWORD
        echo 
        echo "............YOUR INPUT............"
        echo -e "$RED Directory Path:$NC $FTP_DIRPATH"
        echo -e "$RED IP Address:$NC $FTP_IPADDRESS"
        echo -e "$RED Images name:$NC" $FTP_IMAGENAME
        echo -e "$RED port:$NC $FTP_PORT"
        echo -e "$RED Username:$NC $FTP_NAME"
        echo -e "$RED Password:$NC******"

        read -p "continue or again[C/A]:" ca
        CA=$(echo "$ca" | tr '[:upper:]' '[:lower:]')
        if [ $CA == c ];then
            #docker
            sudo docker pull pionux/ftp:0.1
            sudo docker run -d -v $FTP_DIRPATH:/home/vsftpd -p 20:20 -p 23:21 -p 47400-47470:47400-47470 -e FTP_USER=$FTP_NAME -e FTP_PASS=$FTP_PASSWORD -e PASV_ADDRESS=$FTP_IPADDRESS --name $FTP_IMAGENAME --restart=always pionux/ftp:0.1
        else 
            ftpread
        fi
    }
    ftpread
fi
}

##call function
check_root
createlog
sethostname
sambainput
pathinput
inputcheck


{
    banner "6" "Installing necessary packages."
    install_package_base || echo -e "${RED}[ FAILED ]${NC} Installing Packages Failed. Please Check log in $LOG" 
    banner "28" "Configuring Network Time Server"
    ntp &>> $LOG || echo -e "${RED}[ FAILED ]${NC} Configuring Network Time Server Failed. Please Check log in $LOG"
    banner "30" "Configuring Dynamic Name Server"
    bind &>> $LOG || echo -e "${RED}[ FAILED ]${NC} Configuring BIND DNS Failed. Please Check log in $LOG"
    banner "45" "Configuring Samba Active Directory Server"
    samba &>> $LOG || echo -e "${RED}[ FAILED ]${NC} Configuring Samba Failed. Please Check log in $LOG" 
    banner "50" "Configuring Keberos Network Authenticator"
    kerberos >> $LOG || echo -e "${RED}[ FAILED ]${NC} Configuring Keberos Failed. Please Check log in $LOG" 
    banner "60" "Configuring Local DNS for Server Usage"
    resolvs  >> $LOG || echo -e "${RED}[ FAILED ]${NC} Configuring Resolv Failed. Please Check log in $LOG" 
    banner "70" "Registering Samba Domain Name in Local"
    hosts >> $LOG || echo -e "${RED}[ FAILED ]${NC} Registering Host Failed. Please Check log in $LOG" 
    banner "75" "Registering Samba Domain Name In Network"
} | whiptail --clear --title "[ KOOMPI AD Server ]" --gauge "Please wait while installing" 10 100 0
    dnsbackup
    #&>> $LOG  || echo -e "${RED}[ FAILED ]${NC} Registering Samba Failed. Please Check log in $LOG" 
{
    banner "85" "Configuring Name Service Swtich Server "   
    nsswitch &>> $LOG || echo -e "${RED}[ FAILED ]${NC} Configuring Name Service Switch Failed. Please Check log in $LOG" 
    banner "90" "Attempts to Implement Active Directory Server"
    testinstall || echo -e "${RED}[ FAILED ]${NC} Attempt to Implement Active Directory Server Failed. Please Check log in $LOG" 
    banner "100" "Installing User Management"
    user_management >> $LOG || echo -e "${RED}[ FAILED ]${NC} Installing User Management Failed. Please Check log in $LOG" 
} | whiptail --clear --title "[ KOOMPI AD Server ]" --gauge "Please wait while installing" 10 100 0

clear
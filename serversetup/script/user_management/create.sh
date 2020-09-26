#!/bin/bash
#This file was create on 22/03/19
# set -x
#==================== function to add group ====================== 
function Group(){
    sudo samba-tool group addmembers $group $username > /dev/null 2>&1
    sudo samba-tool group addmembers network $username > /dev/null 2>&1
    sudo samba-tool group addmembers video $username > /dev/null 2>&1
    sudo samba-tool group addmembers storage $username > /dev/null 2>&1
    sudo samba-tool group addmembers lp $username > /dev/null 2>&1
    sudo samba-tool group addmembers audio $username > /dev/null 2>&1
    # sudo samba-tool group addmembers wheel $username > /dev/null 2>&1
}
#==================== Function create folder ====================== 
function folder(){
    mkdir -p  /home/samba/home/$username
    chown -R $username:$group  /home/samba/home/$username
    chmod 700  /home/samba/home/$username
}
#==================== function expiry ====================== 
function expiry(){
    if [[ "$Expiry" == "Disable" ]]
    then 
        sudo samba-tool user setexpiry $username  --noexpiry
    else
        sudo samba-tool user setexpiry --days=$Day $username  
    fi 

} 

OLDIFS=$IFS
IFS="	"
while read username fistname surname passwd ou group jobtitle emailaddress Expiry Day
do 
    echo -e "\e[1;33m =====> Creating user $username <=====\e[0m\n\
    Username        : $username \n\
    Firstname       : $fistname \n\
    Surname         : $surname \n\
    Password        : "********" \n\
    OU              : $ou \n\
    Group           : $group \n\
    Job Title       : $jobtitle \n\
    Email           : $emailaddress \n\
    Expriy password : $Expiry \n\
    Day             : $Day  \n"
#Create 
    finduser=$(sudo samba-tool user list | grep $username)
    if [[ $username == $finduser ]];then 
        printf "$username : already exists\n\n"
    else 
        findou=$(sudo samba-tool ou list | grep $ou | awk -F'=' '{print $2}')
        if [[ $findou != $ou ]];then
            printf "$ou :dose not already exists.\n\n"
            echo "Please create ou=$ou before add user."
            exit;
        else
            findgroup1=$(sudo samba-tool user list | grep $group)
            if [[ $findgroup1 == $group ]];then 
                echo "Name Group $group is the same name user."
                echo "Please change name group."
                exit
            else 
                findgroup=$(sudo samba-tool group list | grep $group)
                if [[ $findgroup != $group ]];then
                    echo "Can't not found group $group"
                    echo "Please create group $group before create user."
                    exit; 
                else 
                    sudo samba-tool user create $username $passwd \
                    --given-name=$fistname --surname=$surname \
                    --unix-home=/home/$username \
                    --job-title="$jobtitle" \
                    --mail-address="$emailaddress" \
                    --login-shell=/bin/fales
                    Group #<--call function group
                    echo "Add group successfully."
                    folder #<-- call function folder
                    echo "create folder successfully."
                    expiry #<-- call function Expiry
                    folder #<-- call function folder
                    #sudo samba-tool user setpassword $username --newpassword=$passwd --must-change-at-next-login  

                fi #end of findgroup    
            fi # end of findgroup with username
        fi #end of findou
    fi #end of finduser
done < $1
IFS=$OLDIFS


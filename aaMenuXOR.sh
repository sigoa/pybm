#!/bin/bash
########################################################################################

#     usage example:       menu     pwd whoami ls ps 

#     giving you a menu with 4 options to execute in bash shell / Konsole 



# call in bash as:       . menu1    # if  menu1  is the file name with this script in it
# usage e.g.:
# menu ls  "ls -l"  "echo  list dir ; clear ; ls -la "   clear
# q, Q or 0 or empty_string i.e. ENTER-key alone     always exits the menu


# click-launch from Dolphin file-manager in KDE: associate shell script  open-action command:  konsole -e %f
# under right-cick,  FILE TYPE OPTIONS,  ...  advanced option, do not tag "run in Terminal"
# so you get a  "open action"  rather than an "execute action" , but it does what you expect.


# to set as a bash lib func  : copy the text  between the upper and lower ###### lines into your ~/.bashrc file
menu()
{
local IFS=$' \t\n'
local num n=1 opt item # cmd

clear

## Use default setting of IFS,  Loop though the command-line arguments --  $(())  no SPACES! 
echo
for item
do
  printf " %3d. %s\n" "$n" "${item%%:*}"
  n=$(($n + 1))
done

## If there are fewer than 10 items, set option to accept key without ENTER
echo    
if [ $# -lt 10 ]
then
  opt=-sn1
else
  opt=
fi

read -p "ENTER quits menu - please choose  1 to $# ==> " $opt num   ## Get response from user

## Check that user entry is valid
case $num in
   [qQ0]   | "" ) clear ; return ;;   ## q, Q or 0 or "" exits
  *[!0-9]* | 0* )                     ## invalid entry

  printf "\aInvalid menu choice : %s\n" "$num" >&2
  return 1
  ;;
esac

echo
if     [ "$num" -le "$#" ]  ## Check that number is <= to the number of menu items
then
  eval  ${!num}             ## eval  "${!num#*:}"  # Execute it using indirect expansion,  breaking stuff  :-(
else
  printf "\aInvalid menu choice: %s\n" "$num" >&2
  return 1
fi
}
############################################################################################## 



#----------------------------------------------------------- 
# "Here-document" containing nice standard keys.dat with 3 chans and 1 nuked ID / pml , dropped into thwe cwd, i.e.  .

# note that a nuked address is kind of useless , since its key was published. It still is kinda broadcast fun though.
# You have no privacy using a nuked key - 
# much like you don't have privacy while using a key which someone has stolen from you.

(
cat <<'EOFherefile'

# omega

EOFherefile
) > omegaXOR.py
#----------------------------------------------------------- 

#local bbb=  '88'
#echo  88 is $bbb


picpost()
{
for file in ./payload/*
do
  python2 ./BM-API-client.py  -e"${file}" -s 'pic sent via API :   ' --es --ttl='60*24*1' -uUSER0000 -pPASSWORD0000
# echo "${file}"
done
}

binpost()
{
  # recipient: [chan] general -t BM-2cW67GEKkHGonXKZLCzouLLxnLym3azS8r
  python2 ./BM-API-client.py  -m"data.zip" -s 'zip sent via API :   ' --es --ttl='60*24*1' -uUSER0000 -pPASSWORD0000 -t BM-2cW67GEKkHGonXKZLCzouLLxnLym3azS8r  
}


picpostPolitics()
{
# Politics -t BM-2cVE8v7L4qb14R5iU2no9oizkx8MpuvRZ7
for file in ./payload/*
do
  python2 ./BM-API-client.py  -e"${file}" -s 'pic sent via API :   ' --es --ttl='60*24*1' -uUSER0000 -pPASSWORD0000  -t BM-2cVE8v7L4qb14R5iU2no9oizkx8MpuvRZ7
# echo "${file}"
done
}

# if you wanna read ure own stuff.  
# if set up as user B already, then
#                                                         python2 ./omegaXOR.py -d ./data.zip   
# is sufficient; no need to changeover from A to B
omegaDecryp()  
{
mv keys   keysa
cp keysa  keysb
cp keysb  keys
rm        keys/config
touch     keys/config
echo b >> keys/config  # switch to "system B"
python2 ./omegaXOR.py -d ./data.zip    
clear
ls -lhg  --sort=time --time=ctime   .
echo 
echo "run some editor (kate) to read the decrypted file now "
}



#   useful in click-launch to add    ; read WAITNOW        #  which will wait for keypress before closing Konsole 

# now actually using the menu:

# modify it to your liking        note you are then on  MASTER  branch , not on the newer  ver. 0.6.3   branch

#  run through the options  1 2 3 4   in this order:   1 2 3 4

menu                                                                                                                         \
'echo " create a one time pad, size 1 MegaByte    " ;  python2 ./omegaXOR.py -g 1               ' \
'echo " edit Message and crypt it  (as user A)    " ;  kate msg ; python2 ./omegaXOR.py -e msg  ' \
'echo "                                           "                                             ' \
'echo " decrypt data.zip and read  (as user B)    " ;  omegaDecryp                              ' \
'echo "                                           "                                             ' \
'echo " launch BM                                 " ;  ./bitmessagemain.py                      ' \
'echo " send crypted data.zip  via bitmessage     " ;  binpost                                  ' \
'echo " post all pics in dir ./payload/*          " ;  picpost                                  ' \
'echo '

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
local num n=1 opt item cmd

clear

## Use default setting of IFS,  Loop though the command-line arguments
echo
for item
do
  printf " %3d. %s\n" "$n" "${item%%:*}"
  n=$(( $n + 1 ))
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




#   useful in click-launch to add    ; read WAITNOW        #  which will wait for keypress before closing Konsole 

# now actually using the menu:

# modify it to your liking        note you are then on  MASTER  branch , not on the newer  ver. 0.6.3   branch

#  run through the options  1 2 3 4   in this order:   1 2 3 4

menu                                                                                                                         \
'echo " one time pad creation 1 MegaByte          " ;  git clone      "https://github.com/Bitmessage/PyBitmessage.git"     ' \
'echo " edit Message and crypt it                 " ;  cd ./PyBitmessage/ ; python2 checkdeps.py ; cd ..                   ' \
'echo " send data.zip crypt via BM                " ;  cp  ./std_keys.dat                   PyBitmessage/src/keys.dat      ' \
'echo " decrypt data.zip and read                 " ;  pushd . ; cd  PyBitmessage/src ; ./bitmessagemain.py ;         popd ' \
'echo "                                           " ;  pushd . ; cd  PyBitmessage/ ; git pull ;                       popd ' \
'echo " launch BM                                 " ;  pushd . ; cd  PyBitmessage/ ; git fetch --all;                 popd ' \
'echo " send pics in pic folder                   " ;  pushd . ; cd  PyBitmessage/ ; git reset --hard origin/master ; popd ' \
'echo "                                           " ;  rm ./PyBitmessage/* ; cd PyBitmessage ; rm -rf man dev build packages desktop ; cd .. ' \
'echo " fill in your own instruction here         "                                                                        '

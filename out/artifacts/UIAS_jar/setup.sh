#!/bin/bash
sudo apt update
sudo apt install default-jre
mkdir passwd_lists

sudo apt install curl
echo "geting dictionary"
curl -L -o passwd_lists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

echo cheking deps
sudo java -jar UIAS.jar  s
echo atempting to install deps
sudo bash dep.sh

echo adding script to PATH
mkdir ~/bin
echo \#\!/bin/bash > netproj
echo "java -jar "$(pwd)"/UIAS.jar">>netproj

cp netproj ~/bin/netproj
chmod +x ~/bin/netproj
cd /
PATH=$PATH:~/bin

echo done! you can now type netproj in terminal to start program if not run: 'PATH=$PATH:~/bin'



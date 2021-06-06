#!/bin/bash
sudo apt update
sudo apt install default-jre
mkdir passwd_lists
mkdir scans

sudo apt install curl
echo "geting dictionary"
curl -L -o passwd_lists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

echo cheking deps
sudo java -jar UIAS.jar  s
echo atempting to install deps
sudo bash dep.sh

echo adding script to PATH

echo \#\!/bin/bash > uias
echo "java -jar "$(pwd)"/UIAS.jar">>uias

chmod +x uias

echo done! you can now type uias in the terminal to start



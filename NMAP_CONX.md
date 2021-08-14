# NMAP
Escaneo inicial TCP
```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn <ip>
```
Escaneo inicial UPD
```bash
nmap -p- -sU --min-rate 10000 --open -n -Pn <ip>
```
Escaneos directos a puertos
```bash
nmap -sS -p500 -sC -sV <ip> -oN udpScan
nmap -sU -p500 -sC -sV <ip> -oN udpScan
```

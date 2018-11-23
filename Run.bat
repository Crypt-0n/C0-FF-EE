@Echo off

:: On execute les commandes en administateur 

:-------------------------------------
REM  -->  Verification des permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> Erreur vous ne possedez pas les droits admin
if '%errorlevel%' NEQ '0' (
    echo Verification des privileges administrateur
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "%~s0", "%params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

set currentpath=%~dp0 
cd %currentpath%
set binary=".\bin"
set VarQuestion="n"
set VarQuestion2="n"

if exist ".\logs" rd .\logs /S /Q

echo.  
echo.            ##################        ) )
echo.            ##################       ( (                   
echo.            #### C0-FF-EE ####        ) )                  
echo.            ##################      (----)-)               
echo.            ##################       \__/-'                
echo.                                                       
echo.  Crypt-0n Forensic Framework for Evidence Enumeration. 
echo.
echo.     Auteur: Julien LEQUEN - jlequen[AT]crypt-0n.fr    
echo.                                                       
echo.      GNU General Public License version 3 (GPLv3)     
echo. _______________________________________________________
echo.
echo.

if not exist ".\logs" mkdir .\logs

echo.                                                         >> .\logs\C0-FF-EE.log
echo.            ##################        ) )                >> .\logs\C0-FF-EE.log
echo.            ##################       ( (                 >> .\logs\C0-FF-EE.log
echo.            #### C0-FF-EE ####        ) )                >> .\logs\C0-FF-EE.log
echo.            ##################      (----)-)             >> .\logs\C0-FF-EE.log
echo.            ##################       \__/-'              >> .\logs\C0-FF-EE.log
echo.                                                         >> .\logs\C0-FF-EE.log
echo.  Crypt-0n Forensic Framework for Evidence Enumeration.  >> .\logs\C0-FF-EE.log
echo.                                                         >> .\logs\C0-FF-EE.log
echo.     Auteur: Julien LEQUEN - jlequen[AT]crypt-0n.fr      >> .\logs\C0-FF-EE.log
echo.                                                         >> .\logs\C0-FF-EE.log
echo.      GNU General Public License version 3 (GPLv3)       >> .\logs\C0-FF-EE.log
echo. _______________________________________________________ >> .\logs\C0-FF-EE.log
echo.                                                         >> .\logs\C0-FF-EE.log
echo.                                                         >> .\logs\C0-FF-EE.log

echo TimeZone : >> .\logs\C0-FF-EE.log
tzutil /g >> .\logs\C0-FF-EE.log
echo. >> .\logs\C0-FF-EE.log


:question
set /p VarQuestion= Lancer le Dump de RAM ? [o]ui/[N]on :
echo.
set /p VarQuestion2= Executer Yara ? [o]ui/[N]on :
echo.

echo %date% %time% : Preparation
echo %date% %time% : Preparation >> .\logs\C0-FF-EE.log

if not exist ".\logs\Bios" mkdir .\logs\Bios
if not exist ".\logs\Registre" mkdir .\logs\Registre
if not exist ".\logs\reseau" mkdir .\logs\Reseau
if not exist ".\logs\Systeme" mkdir .\logs\Systeme
if not exist ".\logs\Systeme\Prefetch" mkdir .\logs\Systeme\Prefetch
if not exist ".\logs\Systeme\autorun" mkdir .\logs\Systeme\Autorun
if not exist ".\logs\Systeme\logs" mkdir .\logs\Systeme\Logs
if not exist ".\logs\disques" mkdir .\logs\Disques

if /I %VarQuestion% NEQ o goto :main
echo %date% %time% : Creation d'un Dump de RAM
echo %date% %time% : Creation d'un Dump de RAM >> .\logs\C0-FF-EE.log
call .\bin\winpmem_1.6.2.exe .\logs\mem_dump.raw >NUL 2> .\logs\debug.log

:main
echo %date% %time% : Etape 01 - Outils SysInternals
echo %date% %time% : Etape 01 - Outils SysInternals >> .\logs\C0-FF-EE.log
call %binary%\autorunsc.exe -a * -accepteula >> .\logs\Systeme\Autorun\SysInternals_autorunsc-a-f.txt 2> .\logs\debug.log
call %binary%\autorunsc.exe -m -s -vt -accepteula >> .\logs\Systeme\Autorun\SysInternals_autorunsc-l-m-v.txt 2> .\logs\debug.log
call %binary%\psfile.exe -accepteula >> .\logs\reseau\SysInternals_psfile.txt 2> .\logs\debug.log
call %binary%\pipelist.exe -accepteula >> .\logs\systeme\SysInternals_pipelist.txt 2> .\logs\debug.log
call %binary%\pslist.exe -accepteula >> .\logs\systeme\SysInternals_pslist.txt 2> .\logs\debug.log
call %binary%\pslist.exe -t -accepteula >> .\logs\systeme\SysInternals_pslist-t.txt 2> .\logs\debug.log
call %binary%\psloggedon.exe -accepteula >> .\logs\systeme\SysInternals_psloggedon.txt 2> .\logs\debug.log
call %binary%\psservice.exe -accepteula >> .\logs\Systeme\Autorun\SysInternals_psservice.txt 2> .\logs\debug.log
call %binary%\Tcpvcon.exe -accepteula >> .\logs\reseau\SysInternals_Tcpvcon.txt 2> .\logs\debug.log
call %binary%\PsInfo.exe -h -s -d  -accepteula >> .\logs\systeme\SysInternals_psinfo-h-s-d.txt 2> .\logs\debug.log

echo %date% %time% : Etape 02 - Collecte d'informations Hardware
echo %date% %time% : Etape 02 - Collecte d'informations Hardware >> .\logs\C0-FF-EE.log
wmic bios list full >> .\logs\Bios\Bios_full.txt 2> .\logs\debug.log
wmic bios get serialnumber >> .\logs\Bios\Bios_SerialNumber.txt 2> .\logs\debug.log
wmic csproduct >> .\logs\Bios\Computer.txt 2> .\logs\debug.log

echo %date% %time% : Etape 03 - Collecte d'informations Systeme
echo %date% %time% : Etape 03 - Collecte d'informations Systeme >> .\logs\C0-FF-EE.log
tzutil /g >> .\logs\Systeme\Fuseau_horaire.txt 2> .\logs\debug.log
echo %date% %time% >> .\logs\Systeme\Date_et_heure.txt 2> .\logs\debug.log
ver >> .\logs\Systeme\Version_Windows.txt 2> .\logs\debug.log
hostname >> .\logs\Systeme\Hostname.txt 2> .\logs\debug.log
wmic computersystem list >> .\logs\Systeme\Info_systeme.txt 2> .\logs\debug.log
msinfo32.exe /report .\logs\Systeme\msinfo32.txt 2> .\logs\debug.log
systeminfo >> .\logs\Systeme\Info_systeme_2.txt 2> .\logs\debug.log
wmic startup list full >> .\logs\Systeme\autorun\Autorun_1.txt 2> .\logs\debug.log
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> .\logs\Systeme\autorun\Autorun_reg.txt 2> .\logs\debug.log
type c:\Autoexec.bat >> .\logs\Systeme\autorun\Autoexec.bat.txt 2> .\logs\debug.log
type c:\Windows\winstart.bat >> .\logs\Systeme\autorun\Autoexec.bat.txt 2> .\logs\debug.log
type %windir%\wininit.ini >> .\logs\Systeme\autorun\wininit.ini.txt 2> .\logs\debug.log
type %windir%\win.ini >> .\logs\Systeme\autorun\win.ini.txt 2> .\logs\debug.log
xcopy C:\Windows\Prefetch\*.* .\logs\Systeme\Prefetch >NUL 2> .\logs\debug.log
wmic qfe >> .\logs\Systeme\KB.txt 2> .\logs\debug.log
net accounts >> .\logs\Systeme\Politique_mot_de_passe.txt 2> .\logs\debug.log
net start >> .\logs\Systeme\Service_lances_1.txt 2> .\logs\debug.log
tasklist /svc /fi "imagename eq svchost.exe" >> .\logs\Systeme\Service_lances_2.txt 2> .\logs\debug.log
net session >> .\logs\Systeme\Sessions_1.txt 2> .\logs\debug.log
net localgroup administrators /domain >> .\logs\Systeme\Admin_AD.txt 2> .\logs\debug.log
wmic ntdomain list brief >> .\logs\Systeme\Controleur_domaine.txt 2> .\logs\debug.log
net localgroup >> .\logs\Systeme\Groups_locaux.txt 2> .\logs\debug.log
net localgroup administrators >> .\logs\Systeme\Groupe_administrators.txt 2> .\logs\debug.log
net localgroup administrateurs >> .\logs\Systeme\Groupe_administrateurs.txt 2> .\logs\debug.log
quser >> .\logs\Systeme\Sessions_2.txt 2> .\logs\debug.log
tasklist.exe /svc >> .\logs\Systeme\Processus_1.txt 2> .\logs\debug.log
wmic process list full >> .\logs\Systeme\Processus_2.txt 2> .\logs\debug.log
wevtutil epl Security .\logs\systeme\logs\security.evtx 2> .\logs\debug.log
wevtutil epl Application .\logs\systeme\logs\Application.evtx 2> .\logs\debug.log
wevtutil epl System .\logs\systeme\logs\System.evtx 2> .\logs\debug.log
schtasks /Query /V /FO list >> .\logs\Systeme\Taches_planifiees.txt 2> .\logs\debug.log
schtasks /Query /V /FO CSV >> .\logs\Systeme\Taches_planifiees.csv 2> .\logs\debug.log
sc.exe queryex >> .\logs\Systeme\Services.txt 2> .\logs\debug.log

echo %date% %time% : Etape 04 - Collecte du Registre
echo %date% %time% : Etape 04 - Collecte du Registre >> .\logs\C0-FF-EE.log
reg.exe export HKLM .\logs\registre\registre_hklm.txt > NUL 2> .\logs\debug.log
reg.exe export HKCU .\logs\registre\registre_hkcu.txt > NUL 2> .\logs\debug.log
reg.exe export HKCR .\logs\registre\registre_hkcr.txt > NUL 2> .\logs\debug.log
reg.exe export HKU .\logs\registre\registre_hku.txt > NUL 2> .\logs\debug.log
reg.exe export HKCC .\logs\registre\registre_hkcc.txt > NUL 2> .\logs\debug.log

echo %date% %time% : Etape 05 - Collecte d'informations disques
echo %date% %time% : Etape 05 - Collecte d'informations disques >> .\logs\C0-FF-EE.log
fsutil usn readjournal c: >> .\logs\disques\usn.log 2> .\logs\debug.log
REM call %binary%\Mft2Csv.exe /Volume:c: /OutputPath:.\logs\disques\MFT > NUL 2> .\logs\debug.log
fsutil fsinfo drives >> .\logs\disques\Info_disques_1.txt 2> .\logs\debug.log
wmic logicaldisk where drivetype=3 get name, freespace, systemname, filesystem, size, volumeserialnumber >> .\logs\disques\Info_disques_2.txt 2> .\logs\debug.log
wmic logicaldisk get description,name,FileSystem,VolumeName,VolumeSerialNumber,FreeSpace,Size >> .\logs\disques\Info_disques_3.txt 2> .\logs\debug.log
dir /x /a:-L /b /s /r c:\ >> .\logs\disques\Dir_disque_C.txt 2> .\logs\debug.log
tree /F /A c:\ >> .\logs\disques\Tree_disque_C.txt 2> .\logs\debug.log

echo %date% %time% : Etape 06 - Collecte d'informations reseau
echo %date% %time% : Etape 06 - Collecte d'informations reseau >> .\logs\C0-FF-EE.log
netsh advfirewall firewall show rule name=all >> .\logs\reseau\firewall.txt 2> .\logs\debug.log
netsh wlan show profiles >> .\logs\reseau\Liste_wifi.txt 2> .\logs\debug.log
netsh wlan export profile folder=.\logs\reseau\ key=clear >NUL 2> .\logs\debug.log
arp.exe -a >> .\logs\reseau\Arp.txt 2> .\logs\debug.log
getmac >> .\logs\reseau\Mac.txt 2> .\logs\debug.log
ipconfig /all >> .\logs\reseau\Ipconfig.txt 2> .\logs\debug.log
ipconfig /displaydns >> .\logs\reseau\Cache_DNS.txt 2> .\logs\debug.log
nbtstat -A 127.0.0.1 >> .\logs\reseau\Services_en_ecoute.txt 2> .\logs\debug.log
nbtstat -n >> .\logs\reseau\Nom_netbios_locaux.txt 2> .\logs\debug.log
nbtstat -S >> .\logs\reseau\Table_de_sessions.txt 2> .\logs\debug.log
nbtstat -c >> .\logs\reseau\Nom_netbios_distants.txt 2> .\logs\debug.log
type %WINDIR%\System32\drivers\etc\hosts>> .\logs\reseau\hosts.txt 2> .\logs\debug.log
net share >> .\logs\reseau\Partages_windows.txt 2> .\logs\debug.log
net use >> .\logs\reseau\Lecteurs_reseau.txt 2> .\logs\debug.log
net file >> .\logs\reseau\Fichiers_ouverts_1.txt 2> .\logs\debug.log
net user >> .\logs\reseau\Utilisateurs_connectés.txt 2> .\logs\debug.log
net view >> .\logs\reseau\Ressources_partages.txt 2> .\logs\debug.log
netstat -ano >> .\logs\reseau\Connexions_reseau_1.txt 2> .\logs\debug.log
netstat -nabo >> .\logs\reseau\Connexions_reseau_2.txt 2> .\logs\debug.log
openfiles /query /v >> .\logs\reseau\Fichiers_ouverts_2.txt 2> .\logs\debug.log
route print >> .\logs\reseau\Routes.txt 2> .\logs\debug.log
netsh winhttp show proxy >> .\logs\reseau\Proxy.txt 2> .\logs\debug.log

if /I %VarQuestion2% NEQ o goto :fin
if not exist ".\logs\Yara" mkdir .\logs\Yara
echo %date% %time% : Etape 07 - Recherche Yara
echo %date% %time% : Etape 07 - Recherche Yara >> .\logs\C0-FF-EE.log
call %binary%\yara32.exe -r -f %binary%\rules.yar c:\ >> .\logs\Yara\Result.txt 2>NUL

:fin

echo %date% %time% : Etape Finale - Compression
echo %date% %time% : Etape Finale - Compression >> .\logs\C0-FF-EE.log
echo. >> .\logs\C0-FF-EE.log
echo La collecte d'informations est terminee ! >> .\logs\C0-FF-EE.log
echo. >> .\logs\C0-FF-EE.log
call .\bin\7z.exe a -sdel .\%COMPUTERNAME%.zip .\logs > NUL 2> NUL

echo.
echo La collecte d'informations est terminee le %date% a %time:~0,2%:%time:~3,2%:%time:~6,2% !
echo.

pause
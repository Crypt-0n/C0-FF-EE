# C0-FF-EE

## Présentation

C0-FF-EE est l'acronyme de : Crypt-0n Forensic Framework for Evidence Enumeration

Cet outil a pour but de collecter des informations d'une machine Windows afin de faciliter la réponse à incident de sécurité.

![](images/C0-FF-EE.png)

## Utilisation

### Mode interactif

Exécutez `Run.bat`

Vous pouvez utiliser des règles Yara perso en les ajoutant dans le fichier `bin\rules.yar`

### Mode "Command Line"

```
C:\C0-FF-EE>Run.bat /?
Aide :

Run.bat [argument]

Merci de renseigner un seul argument

Liste des arguments :
  --dump : Lance C0-FF-EE avec Dump de RAM
  --yara : Lance C0-FF-EE avec Yara
  --all  : Lance C0-FF-EE avec Dump de RAM et Yara

Sans argument C0-FF-EE s'execute en mode interactif
```
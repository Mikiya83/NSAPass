# NSA Pass

[![GuardRails badge](https://badges.production.guardrails.io/Mikiya83/NSAPass.svg)](https://www.guardrails.io)

_Not Sure About your PASSword_ est un outil à usage interne pour tester si votre mot de passe est un mot de passe qui a fuité dans une ou plusieurs brèches rendues publiques.  
L'outil est un fork local de https://haveibeenpwned.com/Passwords  
Les données sont transmises uniquement sur le réseau local une fois configuré, au format hashé sha1, et dans une connexion sécurisée. Aucune donnée n'est enregistrée à l'exception d'un compteur de requêtes afin de mesurer l'intérêt de l'outil sur votre réseau.  

![Cat](../assets/home.png)
![Cat](../assets/fail.png)

# Installation
Debian 9 ou supérieure conseillée.
## Paquet à installer
> apt-get install nginx php-fpm mysql-server php-mysql

## Initialisation de la base de donnée
Générer préalablement un mot de passe pour l'accès à la base de donnée. Par exemple avec l'outil `makepasswd`  
> makepasswd --chars=24

Puis configurer la base de donnée mysql  
> CREATE USER 'nsapass'@'localhost' IDENTIFIED BY '\<password\>';  
> CREATE DATABASE nsapass;  
> GRANT ALL ON nsapass.\* TO 'nsapass'@'localhost';  
> FLUSH PRIVILEGES;  

Enfin mettre à jour le mot de passe dans le fichier `www/config.ini`  

## Import de la base des mots de passe
Le fichier qui les contient est trouvable sur le site original https://haveibeenpwned.com/Passwords , suivre les instructions en bas.
Attention il est volumineux !

Le format du fichier d'import doit être de la forme :  
> \<hash\>:\<occurence\>  

On crée d'abord les tables vides:

>CREATE TABLE IF NOT EXISTS password (hash VARCHAR(40) NOT NULL PRIMARY KEY, count INT UNSIGNED);
>CREATE TABLE IF NOT EXISTS meta (req_count INT UNSIGNED, db_version VARCHAR(5), nb_password INT UNSIGNED);

Ensuite le fichier doit être importé directement sur le serveur avec la requête suivante  
> USE nsapass;  
> LOAD DATA INFILE 'pwned-passwords-ordered-2.0.txt' REPLACE INTO TABLE password FIELDS TERMINATED BY ':';  

L'import prend environ 2h...  

### Renseignement de la table "meta"

Une fois l'import des mots de passe effectué, renseigner la table `meta` avec les informations suivante :
* Nombre de mot de passe dans la base  
> TODO

* Version de la base  
> TODO

* Date de dernier import  
> TODO



# TP Noté ASI331

Tout le code est contenu dans ecdh.py et nécessite l'installation de la librairie *sagemath*, en version **10.1**. De mon côté, `sage` est une commande bash, `#! /usr/bin/env sage` a été rajouté au début du fichier. Le fichier python est donc lancé par `sage` avec son propre interpréteur Python3.

## Requirements

Autre que `sage`, la seule librairie externe utilisée est `multipledispatch` :
- Si lancement avec l'interpréteur Python3 du système : `python3 -m pip install multipledispatch`
- Si lancement avec `sage` : `sage --python3 -m pip install multipledispatch`

## Utilisation

Le fichier dispose d'une aide visible avec `./ecdh.py -h`, mais voici un récapitulatif des différentes commandes :
- `gencurve [-o OUTPUT_FILE(default=curve.json)] <number of bits for the prime=256> <smoothness criterion=100000>` : génère une courbe elliptique G de taille N valide ainsi qu'un point B générateur d'un sous-groupe de taille r premier avec r|N, et N non N/100000-friable. Autrement dit, le plus grand diviseur premier de N est r, avec r > N/100000.
- `genprivkey [-o OUTPUT_FILE(default=privkey.json)] <file with the generated curve>`: génère une clé aléatoire de Diffie-Hellman ainsi que sa clé publique associée à partir de la courbe elliptique stockée dans le fichier et générée à l'étape précédente.
- `genenckey [-o OUTPUT_FILE(default=key.txt)] <personnal private keyfile> <other public key file> <curve file>`: génère la clé de session associée à clé privée personnelle, la clé publique du correspondant ainsi que la courbe elliptique associée
- `encrypt [-o OUTPUT_FILE(default=encrypted.txt)] <plain text file> <key file> <IV file>`: chiffe le message contenu dans `<plain text file>` avec AES-256-CBC, la clé donnée et le vecteur d'initialisation donné (tous deux stockés dans un fichier)
- `decrypt [-o OUTPUT_FILE(default=decrypted.txt)] <ciffer text file> <key file> <IV file>`: déchiffe le message contenu dans `<ciffer text file>` avec AES-256-CBC, la clé donnée et le vecteur d'initialisation donné (tous deux stockés dans un fichier)
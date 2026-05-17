#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système d'Échange de Fichiers Sécurisé - Client Sécurisé (Host A)
================================================================

Ce script simule le client ("Host A") qui :
1. Génère une clé symétrique ChaCha20 de 256 bits.
2. Chiffre un fichier local à l'aide de ChaCha20 avec un nonce aléatoire de 16 octets.
3. Téléverse le fichier chiffré (.enc) de manière sécurisée vers le serveur FastAPI
   (https://localhost:8443/upload) en validant son certificat TLS grâce à 'ca_cert.pem'.
4. Télécharge le fichier chiffré depuis le serveur (https://localhost:8443/download/...)
   et le déchiffre localement pour restaurer le document d'origine.

Sécurité ChaCha20 :
-------------------
- ChaCha20 est un chiffrement par flux (stream cipher) très rapide et sécurisé.
- Il nécessite une clé de 256 bits (32 octets) et un nonce de 128 bits (16 octets).
- Le nonce DOIT être unique pour chaque fichier chiffré avec la même clé. Sa réutilisation
  permettrait à un attaquant de casser le chiffrement par simple analyse XOR.
- Le nonce n'est pas secret. Il est stocké au tout début du fichier chiffré (.enc)
  (les 16 premiers octets) afin d'être extrait lors du déchiffrement.

Auteur: Développeur Python expert en Cryptographie
"""

import os
import requests
from custom_crypto import chacha20_encrypt, chacha20_decrypt

# Configuration du client
SERVER_URL = "http://localhost:8080"
NONCE_SIZE = 12  # Taille du nonce ChaCha20 IETF (12 octets / 96 bits)
KEY_SIZE = 32    # Taille de la clé ChaCha20 (32 octets / 256 bits)


def generer_cle_chacha20() -> bytes:
    """
    Génère une clé symétrique aléatoire de 256 bits (32 octets).
    Utilise os.urandom pour garantir une qualité cryptographique (CSPRNG).
    """
    print("[+] Génération d'une clé symétrique ChaCha20 de 256 bits...")
    return os.urandom(KEY_SIZE)


def chiffrer_fichier(chemin_source: str, chemin_destination: str, cle: bytes) -> None:
    """
    Chiffre le contenu d'un fichier avec l'algorithme ChaCha20.
    
    Format du fichier de sortie :
    [ Nonce (12 octets) ] + [ Données chiffrées (Taille variable) ]
    """
    if not os.path.exists(chemin_source):
        raise FileNotFoundError(f"Le fichier source {chemin_source} n'existe pas.")

    print(f"[+] Chiffrement du fichier '{chemin_source}'...")
    
    # 1. Lire le contenu en clair
    with open(chemin_source, "rb") as f:
        donnees_claires = f.read()

    # 2. Générer un nonce (IV) aléatoire de 12 octets
    # Il est impératif que ce nonce soit unique pour chaque opération de chiffrement !
    nonce = os.urandom(NONCE_SIZE)

    # 3. Chiffrer les données via notre ChaCha20 custom
    donnees_chiffrees = chacha20_encrypt(donnees_claires, cle, nonce)

    # 4. Sauvegarder : Nonce (12 octets) + Données chiffrées
    with open(chemin_destination, "wb") as f:
        f.write(nonce)
        f.write(donnees_chiffrees)

    print(f"[OK] Fichier chiffré sauvegardé sous '{chemin_destination}' (Taille : {os.path.getsize(chemin_destination)} octets)")
 
 
def upload_fichier(chemin_chiffre: str) -> str:
    """
    Téléverse le fichier chiffré (.enc) sur le serveur FastAPI.
    """
    if not os.path.exists(chemin_chiffre):
        raise FileNotFoundError(f"Le fichier chiffré {chemin_chiffre} n'existe pas.")

    url_upload = f"{SERVER_URL}/upload"
    nom_fichier = os.path.basename(chemin_chiffre)

    print(f"[+] Téléversement de '{nom_fichier}' vers {url_upload}...")

    # Préparation des fichiers pour la requête multipart/form-data
    files = {
        'file': (nom_fichier, open(chemin_chiffre, 'rb'), 'application/octet-stream')
    }

    try:
        # Envoi de la requête POST HTTP standard
        reponse = requests.post(
            url_upload,
            files=files
        )
        
        # Fermeture propre du fichier téléversé
        files['file'][1].close()

        # Vérification du statut HTTP
        reponse.raise_for_status()
        
        print("[OK] Téléversement réussi !")
        print(f"    Réponse du serveur : {reponse.json()}")
        return nom_fichier

    except requests.exceptions.RequestException as req_err:
        print(f"[!] Erreur de communication réseau : {req_err}")
        raise
 
 
def telecharger_et_dechiffrer(nom_fichier_enc: str, chemin_restaure: str, cle: bytes) -> None:
    """
    Télécharge un fichier chiffré depuis le serveur FastAPI et le déchiffre localement.
    Extrait le nonce de 12 octets présent au début avant d'opérer le déchiffrement ChaCha20.
    """
    url_download = f"{SERVER_URL}/download/{nom_fichier_enc}"
    print(f"[+] Téléchargement de '{nom_fichier_enc}' depuis {url_download}...")

    try:
        # Requête GET HTTP standard
        reponse = requests.get(url_download)
        reponse.raise_for_status()

        contenu_binaire = reponse.content
        taille_contenu = len(contenu_binaire)

        if taille_contenu < NONCE_SIZE:
            raise ValueError("Le fichier téléchargé est trop petit pour contenir un nonce ChaCha20 valide.")

        print(f"[+] Fichier reçu ({taille_contenu} octets). Déchiffrement en cours...")

        # 1. Extraire le nonce (les 12 premiers octets)
        nonce = contenu_binaire[:NONCE_SIZE]
        
        # 2. Extraire le reste (les données chiffrées)
        donnees_chiffrees = contenu_binaire[NONCE_SIZE:]

        # 3. Déchiffrer via notre ChaCha20 custom
        donnees_claires = chacha20_decrypt(donnees_chiffrees, cle, nonce)

        # 4. Sauvegarder le fichier restauré
        with open(chemin_restaure, "wb") as f:
            f.write(donnees_claires)

        print(f"[OK] Fichier déchiffré avec succès ! Sauvegardé sous '{chemin_restaure}'")

    except requests.exceptions.RequestException as req_err:
        print(f"[!] Erreur lors du téléchargement du fichier : {req_err}")
        raise
    except Exception as e:
        print(f"[!] Erreur lors du déchiffrement : {e}")
        raise


if __name__ == "__main__":
    print("=" * 70)
    print("      CLIENT SECURISE (HOST A) - CHA-CHA20 & PKI SIMULATION")
    print("=" * 70)

    # 1. Génération de la clé symétrique en mémoire
    cle_symetrique = generer_cle_chacha20()
    print(f"[i] Clé symétrique générée (hex) : {cle_symetrique.hex()}")

    # Création d'un fichier de test local à chiffrer
    fichier_test = "document_confidentiel.txt"
    fichier_chiffre = "document_confidentiel.txt.enc"
    fichier_restaure = "restaure_fichier.txt"

    with open(fichier_test, "w", encoding="utf-8") as f:
        f.write("CONFIDENTIEL - PROJET SECURE FILE EXCHANGE\n"
                "Ce message est hautement confidentiel et est chiffré de bout en bout "
                "avec l'algorithme ChaCha20. Seul le client possédant la clé symétrique "
                "peut restaurer ce message en clair.")

    print(f"\n[+] Fichier de test '{fichier_test}' créé avec succès.")

    try:
        # 2. Chiffrement local
        chiffrer_fichier(fichier_test, fichier_chiffre, cle_symetrique)
        
        print("\n" + "-" * 50)
        print("[!] Note : Pour exécuter le téléversement (Upload) et le téléchargement (Download),")
        print("    le serveur FastAPI doit être lancé et écouter sur https://localhost:8443.")
        print("    Voulez-vous tenter la connexion maintenant ? (Entrée pour tester, Ctrl+C pour quitter)")
        print("-" * 50)
        
        # Pause interactive pour laisser le choix à l'utilisateur si le serveur n'est pas encore actif
        input("\nAppuyez sur Entrée pour tenter de communiquer avec le serveur...")

        # 3. Téléversement
        nom_fichier_televerse = upload_fichier(fichier_chiffre)

        # 4. Téléchargement et Déchiffrement
        print()
        telecharger_et_dechiffrer(nom_fichier_televerse, fichier_restaure, cle_symetrique)

        # 5. Vérification de l'intégrité
        with open(fichier_restaure, "r", encoding="utf-8") as f:
            contenu = f.read()
        print("\n[OK] Contenu du fichier restauré :")
        print("-" * 40)
        print(contenu)
        print("-" * 40)

    except KeyboardInterrupt:
        print("\n[i] Opération annulée par l'utilisateur.")
    except Exception as err:
        print(f"\n[!] Fin de la simulation en raison d'une erreur (Serveur probablement hors-ligne) : {err}")
        print("    Le chiffrement et la sauvegarde locale de '.enc' ont tout de même été effectués avec succès !")

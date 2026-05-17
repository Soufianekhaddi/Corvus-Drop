#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Corvus Drop - Initialisation de la PKI Customisée FROM SCRATCH
=============================================================
Ce script permet d'initialiser une PKI (Public Key Infrastructure) locale de test
entièrement codée de A à Z en pur Python sans dépendance externe.
"""

import os
import getpass
from custom_crypto import (
    serialize_custom_private_key,
    create_custom_certificate,
    ecc_mult,
    G,
    P_256_N
)

# Noms des fichiers de sortie
CA_KEY_FILE = "ca_private_key.pem"
CA_CERT_FILE = "ca_cert.pem"
SERVER_KEY_FILE = "server_private_key.pem"
SERVER_CERT_FILE = "server_cert.pem"


def generate_ecc_key_pair():
    """
    Génère une paire de clés ECC (scalaires privés d) de manière sécurisée (CSPRNG).
    """
    print("[+] Génération d'une paire de clés ECC (NIST P-256) from scratch...")
    # Clé privée = entier aléatoire dans [1, N-1]
    private_key = int.from_bytes(os.urandom(32), "big") % P_256_N
    if private_key == 0:
        private_key = 1
    return private_key


def save_pem_file(filename, data):
    """
    Sauvegarde des données au format PEM/JSON dans un fichier.
    """
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data)
    print(f"[OK] Fichier sauvegardé : {filename}")


def main():
    print("=" * 70)
    print("  INITIALISATION DE LA PKI CUSTOMISÉE FROM SCRATCH (NIST P-256)")
    print("=" * 70)

    try:
        # Étape 1 : Génération de la Root CA
        print("\n--- ÉTAPE 1 : AUTORITÉ DE CERTIFICATION RACINE (ROOT CA) ---")
        ca_private_key = generate_ecc_key_pair()
        ca_public_key = ecc_mult(ca_private_key, G)
        
        # Étape 2 : Génération du Certificat Serveur
        print("\n--- ÉTAPE 2 : CERTIFICAT SERVEUR (HOST B) ---")
        server_private_key = generate_ecc_key_pair()
        server_public_key = ecc_mult(server_private_key, G)

        # Étape 3 : Saisie du mot de passe pour la CA Racine
        print("\n--- ÉTAPE 3 : EXPORTATION ET SÉCURISATION DES FICHIERS ---")
        print("\n[+] SÉCURISATION DE LA CA RACINE (Chiffrement de la Clé Privée par KDF)")
        
        env_password = os.environ.get("CA_PASSWORD")
        if env_password:
            password = env_password
            print("[i] Utilisation du mot de passe de l'autorité racine fourni via variable d'environnement CA_PASSWORD.")
        else:
            while True:
                password = getpass.getpass("Définissez un mot de passe fort pour chiffrer la clé privée de la Root CA : ")
                if len(password) < 8:
                    print("[!] Le mot de passe doit faire au moins 8 caractères.")
                    continue
                confirm = getpass.getpass("Confirmez le mot de passe : ")
                if password != confirm:
                    print("[!] Les mots de passe ne correspondent pas. Réessayez.")
                    continue
                break

        # Chiffrement de la clé privée CA Racine
        ca_private_pem = serialize_custom_private_key(ca_private_key, password)
        # Clé privée du serveur non chiffrée
        server_private_pem = serialize_custom_private_key(server_private_key)

        # Création des certificats customisés signés par ECDSA from scratch
        ca_cert_pem = create_custom_certificate("Local Root CA", "Local Root CA", 365, ca_public_key, ca_private_key)
        server_cert_pem = create_custom_certificate("localhost", "Local Root CA", 30, server_public_key, ca_private_key)

        # Écriture dans les fichiers PEM
        save_pem_file(CA_KEY_FILE, ca_private_pem)
        save_pem_file(CA_CERT_FILE, ca_cert_pem)
        save_pem_file(SERVER_KEY_FILE, server_private_pem)
        save_pem_file(SERVER_CERT_FILE, server_cert_pem)

        # Copie automatique du certificat CA vers le client pour la validation TLS/simulation
        client_dir = os.path.join("..", "client")
        if os.path.exists(client_dir):
            client_ca_path = os.path.join(client_dir, CA_CERT_FILE)
            save_pem_file(client_ca_path, ca_cert_pem)
            print(f"[+] Certificat CA sauvegardé pour le client dans : {client_ca_path}")

        print("\n" + "=" * 70)
        print("[+] PKI customisée initialisée avec succès !")
        print(f"    - Clé privée CA   : {CA_KEY_FILE} (Chiffrée KDF + ChaCha20)")
        print(f"    - Certificat CA   : {CA_CERT_FILE} (Auto-signé ECDSA)")
        print(f"    - Clé privée Serv : {SERVER_KEY_FILE}")
        print(f"    - Certificat Serv : {SERVER_CERT_FILE} (Signé par Root CA)")
        print("=" * 70)

    except Exception as e:
        print(f"\n[!] Une erreur est survenue lors de l'initialisation de la PKI : {e}")


if __name__ == "__main__":
    main()

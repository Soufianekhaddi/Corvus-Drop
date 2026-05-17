#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système d'Échange de Fichiers Sécurisé - Initialisation d'une PKI Locale de Test
==============================================================================

Ce script permet d'initialiser une PKI (Public Key Infrastructure) locale de test.
Il génère une Autorité de Certification Racine (Root CA) et un certificat serveur
signé par cette autorité pour sécuriser les communications (ex: HTTPS, TLS).

Concepts cryptographiques mis en œuvre :
----------------------------------------
1. Cryptographie sur les courbes elliptiques (ECC) :
   - Plus performante et offre une sécurité équivalente à RSA avec des clés beaucoup plus courtes.
   - Utilisation de la courbe SECP384R1 (recommandée par le NIST / ANSSI pour un niveau de sécurité élevé).

2. Autorité de Certification Racine (Root CA) :
   - L'ancre de confiance de notre PKI locale. Son certificat est auto-signé.
   - Extension 'Basic Constraints' avec 'ca=True' (indique que ce certificat peut signer d'autres certificats).

3. Certificate Signing Request (CSR) :
   - Document envoyé par une entité (le serveur) à la CA pour demander la signature d'un certificat.
   - Contient la clé publique du serveur et son identité (Common Name).

4. Certificat X.509 Serveur :
   - Certificat final signé par la Root CA contenant les extensions de sécurité nécessaires :
     * Basic Constraints : ca=False (ne peut pas signer d'autres certificats).
     * Key Usage : Signature numérique, chiffrement de clé, accord de clé.
     * Subject Alternative Name (SAN) : Indispensable aujourd'hui pour la validation par les navigateurs modernes
       (autorise l'usage de 'localhost' et '127.0.0.1').

Auteur: Ingénieur en Cryptographie & Cybersécurité
"""

import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Configuration de la PKI
CURVE = ec.SECP384R1()  # Courbe NIST P-384
HASH_ALGORITHM = hashes.SHA384()  # SHA-384 pour correspondre à la force de la courbe SECP384R1

# Noms des fichiers de sortie
CA_KEY_FILE = "ca_private_key.pem"
CA_CERT_FILE = "ca_cert.pem"
SERVER_KEY_FILE = "server_private_key.pem"
SERVER_CERT_FILE = "server_cert.pem"


def generate_ecc_key_pair():
    """
    Génère une paire de clés ECC (Elliptic Curve Cryptography) hautement sécurisée.
    Utilise la courbe SECP384R1.
    """
    print("[+] Génération d'une paire de clés ECC (SECP384R1)...")
    private_key = ec.generate_private_key(CURVE)
    return private_key


def create_root_ca(private_key):
    """
    Génère un certificat de CA Racine (Root CA) auto-signé.
    Le certificat est valide pour 365 jours.
    """
    print("[+] Génération du certificat Root CA auto-signé...")
    
    # Définition du sujet et de l'émetteur (identiques car auto-signé)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "IDF"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Exchange Co"),
        x509.NameAttribute(NameOID.COMMON_NAME, "EMSI RS"),
    ])

    # Configuration des dates de validité
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now
    valid_to = now + datetime.timedelta(days=365)

    # Construction du certificat X.509
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        # Extension essentielle : Indique explicitement que c'est une CA et qu'elle peut signer
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        # Extension d'usage de clé pour une CA (KeyCertSign et CRLSign)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Identifiant de la clé du sujet (Subject Key Identifier)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )

    # Signature du certificat avec notre propre clé privée Root CA
    root_cert = cert_builder.sign(
        private_key=private_key,
        algorithm=HASH_ALGORITHM,
    )
    
    return root_cert


def create_server_csr(server_private_key):
    """
    Génère une demande de signature de certificat (CSR) pour le serveur.
    Common Name (CN) : localhost
    """
    print("[+] Génération de la demande de signature de certificat (CSR) pour le serveur...")
    
    # Identité du serveur
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "IDF"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Exchange Co"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # Construction de la CSR
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    
    # Signature de la CSR par la clé privée du serveur
    csr = csr_builder.sign(
        private_key=server_private_key,
        algorithm=HASH_ALGORITHM,
    )
    
    return csr


def sign_server_csr(csr, ca_cert, ca_private_key):
    """
    Signe la CSR du serveur à l'aide de la Root CA.
    Génère un certificat X.509 final pour le serveur valide 30 jours.
    """
    print("[+] Signature du CSR serveur par la Root CA...")
    
    # Dates de validité (30 jours)
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now
    valid_to = now + datetime.timedelta(days=30)

    # Construction du certificat serveur
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        # Extension essentielle : Ce n'est PAS une CA
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Extension Key Usage pour un serveur Web (Chiffrement et signature numérique)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extension Extended Key Usage (Server Authentication)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        # Subject Alternative Names (SAN) - Crucial pour la validation TLS moderne
        # Permet de valider 'localhost' et l'IP '127.0.0.1'
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        # Identifiants de clé pour l'autorité et le sujet
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    # Signature finale du certificat serveur avec la clé privée de la CA racine
    server_cert = cert_builder.sign(
        private_key=ca_private_key,
        algorithm=HASH_ALGORITHM,
    )
    
    return server_cert


def save_pem_file(filename, data, is_private_key=False):
    """
    Sauvegarde des données au format PEM dans un fichier.
    Gère les permissions du fichier (droits restreints en lecture pour les clés privées).
    """
    # Écriture du fichier PEM
    with open(filename, "wb") as f:
        f.write(data)
    
    # Gestion des permissions de base sous Unix/Linux/macOS
    # Les clés privées ne doivent être lisibles que par leur propriétaire (0600 / stat.S_IRUSR | stat.S_IWUSR)
    # Sur Windows, chmod a un effet limité mais nous appliquons tout de même la restriction standard POSIX.
    if os.name == 'posix':
        if is_private_key:
            os.chmod(filename, 0o600)  # Lecture/Écriture uniquement pour le propriétaire
            print(f"[i] Permissions restreintes appliquées sur {filename} (0600)")
        else:
            os.chmod(filename, 0o644)  # Lecture pour tout le monde, écriture propriétaire
    elif os.name == 'nt' and is_private_key:
        # Note pour Windows: Les permissions avancées s'appuient sur les ACLs NTFS
        # Nous informons simplement l'utilisateur de la sensibilité de ces fichiers.
        print(f"[i] Fichier {filename} créé sur Windows. Pensez à restreindre l'accès NTFS si nécessaire.")


def main():
    print("=" * 70)
    print("  INITIALISATION DE LA PKI LOCALE DE TEST (ECC SECP384R1)")
    print("=" * 70)

    try:
        # Étape 1 : Génération de la Root CA
        print("\n--- ÉTAPE 1 : AUTORITÉ DE CERTIFICATION RACINE (ROOT CA) ---")
        ca_private_key = generate_ecc_key_pair()
        ca_cert = create_root_ca(ca_private_key)
        
        # Étape 2 : Génération du Certificat Serveur
        print("\n--- ÉTAPE 2 : CERTIFICAT SERVEUR (HOST B) ---")
        server_private_key = generate_ecc_key_pair()
        server_csr = create_server_csr(server_private_key)
        server_cert = sign_server_csr(server_csr, ca_cert, ca_private_key)

        # Étape 3 : Exportation au format PEM
        print("\n--- ÉTAPE 3 : EXPORTATION ET SÉCURISATION DES FICHIERS PEM ---")
        
        # Chiffrement par mot de passe de la clé privée de l'autorité racine (Root CA) via KDF robuste
        import getpass
        print("\n[+] SÉCURISATION DE LA CA RACINE (Chiffrement de la Clé Privée par KDF)")
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

        password_bytes = password.encode("utf-8")
        ca_private_pem = ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
        )
        
        server_private_pem = server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Sérialisation des certificats
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)

        # Écriture dans les fichiers PEM
        save_pem_file(CA_KEY_FILE, ca_private_pem, is_private_key=True)
        save_pem_file(CA_CERT_FILE, ca_cert_pem, is_private_key=False)
        save_pem_file(SERVER_KEY_FILE, server_private_pem, is_private_key=True)
        save_pem_file(SERVER_CERT_FILE, server_cert_pem, is_private_key=False)

        # Copie automatique du certificat CA vers le client pour la validation TLS
        client_dir = os.path.join("..", "client")
        if os.path.exists(client_dir):
            client_ca_path = os.path.join(client_dir, CA_CERT_FILE)
            save_pem_file(client_ca_path, ca_cert_pem, is_private_key=False)
            print(f"[+] Certificat CA également sauvegardé pour le client dans : {client_ca_path}")

        print("\n" + "=" * 70)
        print("[+] PKI locale initialisée avec succès !")
        print(f"    - Clé privée CA   : {CA_KEY_FILE}")
        print(f"    - Certificat CA   : {CA_CERT_FILE} (Valide : 365 jours)")
        print(f"    - Clé privée Serv : {SERVER_KEY_FILE}")
        print(f"    - Certificat Serv : {SERVER_CERT_FILE} (Valide : 30 jours, SAN : localhost, 127.0.0.1)")
        print("=" * 70)

    except Exception as e:
        print(f"\n[!] Une erreur est survenue lors de l'initialisation de la PKI : {e}")


if __name__ == "__main__":
    main()

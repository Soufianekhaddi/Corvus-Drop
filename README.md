# 🛡️ Corvus Drop

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.25%2B-FF4B4B.svg)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/Cryptography-ECC_&_ChaCha20-orange.svg)](https://cryptography.io/)

**Corvus Drop** est un laboratoire et un système de transfert de fichiers chiffrés de bout en bout hautement sécurisé, propulsé par une architecture client-serveur moderne intégrant des algorithmes de cryptographie de pointe (courbes elliptiques ECC et chiffrement symétrique par flux ChaCha20) sécurisés par un canal asymétrique TLS natif.

L'application propose également un outil d'inspection et d'analyse TLS/X.509 en temps réel pour n'importe quel site web.

---

## 🌟 Fonctionnalités Clés

- **🔐 Cryptographie Hybride Moderne** :
  - **Chiffrement symétrique de bout en bout** : Utilisation de **ChaCha20** (clé de 256 bits et nonce aléatoire de 128 bits unique par fichier). Le chiffrement s'exécute uniquement en mémoire côté client avant tout envoi.
  - **Cryptographie sur Courbes Elliptiques (ECC)** : Paire de clés basées sur la courbe **SECP384R1** (recommandée par le NIST / ANSSI) pour la PKI locale.
- **📜 PKI (Public Key Infrastructure) Locale** :
  - Génération d'une autorité de certification racine auto-signée (Root CA).
  - Génération de Certificate Signing Requests (CSR) et signature de certificats serveurs avec gestion des Subject Alternative Names (SAN) pour un HTTPS parfait sans avertissement de sécurité.
- **📡 Serveur API FastAPI HTTPS Premium** :
  - Transfert binaire asynchrone sécurisé par TLS natif (Uvicorn).
  - Dashboard d'administration premium avec design futuriste (thème cyber sombre).
  - Explorateur de fichiers chiffrés avec option de téléchargement et suppression sécurisée.
- **🎨 Interface Graphique Streamlit Premium** :
  - **Inspecteur HTTPS Réel** : Effectue un Handshake TLS avec n'importe quel site internet public, décode et affiche en temps réel les détails cryptographiques du certificat X.509 distant.
  - **Simulateur PKI Interactif** : Créez et observez les étapes d'une CA racine.
  - **Coffre-fort client** : Interface d'upload/download et de chiffrement/déchiffrement assistée en temps réel.
- **🔄 Synchronisation Intelligente (Smart Sync)** :
  - Les clés et certificats générés par la PKI ou via l'interface Streamlit se synchronisent automatiquement entre les dossiers clients et serveurs pour un fonctionnement immédiat sans copies manuelles.

---

## 📂 Structure du Projet

```text
Corvus Drop/
├── 📂 client/              # --- CÔTÉ CLIENT (Host A) ---
│   ├── client.py           # Script client CLI de test (chiffrement & upload)
│   ├── interface.py        # Interface premium Streamlit (ECC Lab & Inspecteur HTTPS)
│   └── ca_cert.pem         # Certificat de confiance de la Root CA
│
└── 📂 server/              # --- CÔTÉ SERVEUR (Host B) ---
    ├── server.py           # Serveur FastAPI HTTPS Premium
    ├── pki_setup.py        # Initialisateur de la PKI locale
    ├── ca_cert.pem         # Certificat de la Root CA
    ├── ca_private_key.pem  # Clé privée Root CA
    ├── server_cert.pem     # Certificat TLS serveur
    ├── server_private_key.pem          # Clé privée TLS serveur
    └── 📂 server_storage/  # Coffre-fort de stockage sécurisé du serveur
```

---

## 🚀 Démarrage Rapide

### 📋 Installation des dépendances

```powershell
pip install fastapi uvicorn requests streamlit cryptography
```

### 1. Initialiser la PKI
Dans le dossier `server/`, générez vos clés et certificats de sécurité :
```powershell
cd server
python pki_setup.py
```

### 2. Lancer le Serveur API HTTPS
Démarrez le serveur FastAPI sous Uvicorn :
```powershell
python server.py
```
* Accédez au dashboard sur : **[https://localhost:8443](https://localhost:8443)**
* Accédez à l'API Swagger sur : **[https://localhost:8443/docs](https://localhost:8443/docs)**

### 3. Lancer l'Interface Graphique Client (Streamlit)
Dans un nouveau terminal, dans le dossier `client/` :
```powershell
cd client
streamlit run interface.py
```
* L'interface s'ouvre automatiquement sur : **`http://localhost:8501`**

---

## 🛡️ Sécurité & Bonnes Pratiques (Production)
Dans le cadre de ce laboratoire local, les clés privées et certificats sont générés sans mot de passe à des fins de démonstration rapide. Pour un déploiement réel en production :
1. Protégez la clé privée de votre Root CA (`ca_private_key.pem`) par mot de passe robuste (KDF / PBKDF2).
2. Restreignez strictement les accès NTFS/POSIX sur les fichiers `.pem`.
3. Intégrez votre Root CA dans le magasin de confiance de vos machines de production (voir l'aide intégrée dans l'onglet 1 de l'application).

---

## 📝 Licence
Ce projet est open-source et développé à des fins académiques et professionnelles en cybersécurité.

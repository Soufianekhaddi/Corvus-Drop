# 🛡️ Corvus Drop - Laboratoire de Cryptographie FROM SCRATCH

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.25%2B-FF4B4B.svg)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/Cryptography-100%25_From_Scratch-success.svg)](#)

## ℹ️ À Propos du Projet

**Corvus Drop** est un laboratoire et un système d'échange de fichiers sécurisés de bout en bout (E2EE) entièrement codé **from scratch** en pur Python. 

Afin de répondre à une exigence académique et d'ingénierie stricte, **aucune bibliothèque cryptographique prédéfinie** (telle que `cryptography`, `PyCryptodome`, `pyOpenSSL`, etc.) n'est utilisée. Toutes les structures de données, les algorithmes de chiffrement symétrique par flux, l'arithmétique modulaire sur les courbes elliptiques et les signatures numériques sont écrits et exécutés au niveau applicatif à partir des principes mathématiques fondamentaux.

---

## 📂 Structure du Projet

Le projet est divisé en deux sections autonomes représentant les deux hôtes communicants :

```text
Corvus Drop/
├── 📂 client/              # --- CÔTÉ CLIENT (Host A) ---
│   ├── client.py           # Script client CLI de simulation E2EE & upload
│   ├── interface.py        # Interface premium Streamlit (ECC Lab & Inspecteur HTTPS)
│   ├── custom_crypto.py    # Moteur de calcul cryptographique autonome (Host A)
│   └── ca_cert.pem         # Copie du certificat de confiance de la Root CA (généré)
│
└── 📂 server/              # --- CÔTÉ SERVEUR (Host B) ---
    ├── server.py           # Serveur FastAPI d'échange de fichiers (HTTP port 8080)
    ├── pki_setup.py        # Script d'initialisation de la PKI customisée
    ├── custom_crypto.py    # Moteur de calcul cryptographique autonome (Host B)
    ├── ca_cert.pem         # Certificat de la Root CA (généré)
    ├── ca_private_key.pem  # Clé privée Root CA chiffrée par KDF (générée)
    ├── server_cert.pem     # Certificat du serveur signé par ECDSA custom (généré)
    ├── server_private_key.pem # Clé privée asymétrique du serveur (générée)
    └── 📂 server_storage/  # Coffre-fort de stockage sécurisé du serveur
```

---

## ⚙️ Spécifications Cryptographiques Mathématiques

### 1. Chiffrement Symétrique : ChaCha20 From Scratch
L'algorithme de chiffrement symétrique par flux **ChaCha20** (RFC 7539) est implémenté de bout en bout :
* **Matrice d'État (64 octets)** : Composée de 4 constantes prédéfinies, de la clé symétrique de 32 octets (256 bits), d'un compteur de bloc de 4 octets et d'un nonce de 12 octets (96 bits).
* **Quart de Ronde (Quarter-Round)** : Opérations arithmétiques pures sur des registres de 32 bits basées sur l'addition modulo $2^{32}$, le OU exclusif (XOR) et les rotations binaires vers la gauche ($<<< 16$, $<<< 12$, $<<< 8$, $<<< 7$).
* **Rondes de Chiffrement** : 20 rondes alternant les colonnes et les diagonales pour assurer une diffusion et une confusion parfaites.

### 2. Cryptographie Asymétrique : ECC (NIST P-256)
L'infrastructure à clés publiques (PKI) repose sur la courbe elliptique standard **NIST P-256** ($y^2 = x^3 - 3x + b \pmod P$) implémentée avec :
* **Addition de Points** et **Doublement de Points** gérant le point à l'infini.
* **Multiplication Scalaire** (méthode Double-and-Add) pour calculer le produit $Q = d \cdot G$ en temps logarithmique stable.
* **Paramètres NIST P-256** codés en dur avec une précision exacte (Modulo premier $P$, Ordre du sous-groupe $N$, Générateur de base $G(x, y)$).

### 3. Signatures Numériques : ECDSA Customisé
Les certificats sont signés numériquement en générant un couple de valeurs $(r, s)$ :
* Calcul du condensat cryptographique via un algorithme de hachage SHA-256.
* Choix d'un nonce éphémère aléatoire $k \in [1, N-1]$.
* Calcul du point de courbe $R = k \cdot G = (x_1, y_1)$ et définition de $r = x_1 \pmod N$.
* Calcul de $s = k^{-1} \cdot (Hash(Msg) + d \cdot r) \pmod N$.
* La vérification du certificat s'effectue en validant que le point $U = (Hash(Msg) \cdot s^{-1}) \cdot G + (r \cdot s^{-1}) \cdot Q$ a pour abscisse $x_u$ tel que $x_u \pmod N == r$.

### 4. KDF & Sécurisation de Clé (PBKDF2-HMAC-SHA256)
Pour se conformer aux standards de haute sécurité, les clés privées d'autorité racine sont chiffrées sur le disque :
* **Dérivation (KDF)** : Implémentation du standard PBKDF2 avec HMAC-SHA256 pour dériver une clé forte de 256 bits à partir d'un mot de passe utilisateur et d'un sel aléatoire de 16 octets (1000 itérations).
* **Chiffrement** : La clé ECC privée dérivée est stockée au format PEM chiffrée par le flux ChaCha20.

---

## 🛠️ Guide de Démarrage & Protocole de Test

### 📋 Prérequis
Installez les bibliothèques minimales nécessaires pour le serveur API et l'interface utilisateur Streamlit :
```bash
pip install fastapi uvicorn requests streamlit
```

---

### Étape 1 : Initialiser la PKI Customisée
Avant de démarrer le serveur, vous devez générer vos autorités de confiance et les clés d'échange :

1. Ouvrez un terminal et placez-vous dans le dossier `server/` :
   ```bash
   cd server
   ```
2. Exécutez le script d'initialisation :
   ```bash
   python pki_setup.py
   ```

> [!IMPORTANT]
> **Sécurisation Forte (KDF) :** Le script vous demandera de définir un mot de passe robuste (minimum 8 caractères). La clé d'autorité racine (`ca_private_key.pem`) sera alors chiffrée par KDF + ChaCha20 avant d'être écrite sur le disque.
> Le certificat public `ca_cert.pem` est automatiquement synchronisé vers le sous-dossier `client/` pour valider la simulation PKI.

---

### Étape 2 : Lancer le Serveur API
Le serveur stocke les fichiers cryptés et expose l'interface d'administration.

1. Toujours dans le dossier `server/`, lancez le serveur FastAPI :
   ```bash
   python server.py
   ```
2. Le serveur s'active instantanément à l'adresse **http://127.0.0.1:8080**. Vous pouvez visualiser l'interface de contrôle web directement dans votre navigateur.

---

### Étape 3 : Valider le Client CLI (Chiffrement et Upload)
Ce test automatique vérifie la validité mathématique du chiffrement ChaCha20 et la connectivité réseau.

1. Ouvrez un **nouveau** terminal et déplacez-vous dans le dossier `client/` :
   ```bash
   cd client
   ```
2. Lancez le script client :
   ```bash
   python client.py
   ```
3. Appuyez sur **Entrée** lorsqu'il vous le demande pour envoyer le fichier. Le client effectue les opérations suivantes :
   * Génère une clé symétrique ChaCha20 cryptographique de 256 bits.
   * Chiffre le fichier localement en ajoutant un nonce unique de 12 octets en tête du fichier.
   * Téléverse le fichier sur le serveur.
   * Récupère le fichier chiffré depuis le serveur et le déchiffre à l'identique !

---

### Étape 4 : Utiliser l'Interface Graphique Streamlit
Le client graphique premium rassemble toutes les interfaces interactives.

1. Dans le dossier `client/`, lancez Streamlit :
   ```bash
   streamlit run interface.py
   ```
2. L'interface s'ouvre à l'adresse par défaut **http://localhost:8501**.

#### 🔬 Expérimentations recommandées dans l'Interface Streamlit :
1. **🌐 Inspecteur HTTPS Réel** : Renseignez le nom de domaine de n'importe quel grand site (ex: `google.com` ou `github.com`) dans le premier onglet. L'application établira un handshake TLS standard et analysera la validité de son certificat sans dépendances externes.
2. **📜 PKI & Certificats ECC** :
   * Générez une Root CA ECC en définissant un mot de passe fort (KDF activée).
   * Émettez un certificat pour votre serveur en entrant le mot de passe défini précédemment pour déverrouiller la Root CA active (validation de signature ECDSA en temps réel !).
   * Analysez le certificat généré via le drag-and-drop de l'**Inspecteur de Certificat customisé** pour lire les coordonnées du point elliptique et les signatures ECDSA $(r, s)$.
3. **🔑 Gestion des Clés** : Générez ou définissez votre clé de chiffrement symétrique ChaCha20 de 256 bits.
4. **📤 Upload / Download** : Envoyez n'importe quel document en clair, observez-le chiffré sur le tableau de bord du serveur, puis téléchargez-le et restaurez-le de manière transparente à l'aide de l'onglet de téléchargement.

---

## 🛡️ Règle de Sécurité Opérationnelle
* **Confidentialité** : Les clés privées générées ne quittent jamais leurs dossiers respectifs.
* **Sécurité à l'arrêt (At Rest)** : La clé privée de la Root CA est chiffrée via notre ChaCha20 avec dérivation KDF PBKDF2 de 1000 rounds.
* **Automatisation** : La clé privée du serveur est stockée en clair sur le serveur pour permettre l'amorçage automatique (bootstrapping standard d'un serveur cloud), sécurisée par les permissions NTFS/POSIX de la machine.

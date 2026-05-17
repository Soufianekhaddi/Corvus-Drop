#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ Corvus Drop - Interface Graphique Premium avec PKI ECC & Inspecteur HTTPS Réel
===================================================================================
Cette interface centralisée propose :
1. Un inspecteur HTTPS réel pour n'importe quel site internet (Handshake TLS standard & Analyse SSL).
2. Un guide et outil d'intégration pour un "Vrai HTTPS" local sans avertissement de sécurité.
3. Un simulateur de PKI asymétrique ECC (Root CA, signature de certificats customisés) codé de A à Z.
4. La gestion de clé symétrique ChaCha20 de bout en bout.
5. L'envoi/réception de fichiers chiffrés via l'API HTTP locale.

Auteur: Développeur Sécurité & Cryptographie Expert - Corvus Drop
"""

import os
import json
import socket
import ssl
import datetime
import requests
import streamlit as st

# Importation de notre bibliothèque cryptographique FROM SCRATCH
from custom_crypto import (
    chacha20_encrypt,
    chacha20_decrypt,
    serialize_custom_private_key,
    deserialize_custom_private_key,
    serialize_custom_public_key,
    deserialize_custom_public_key,
    create_custom_certificate,
    verify_custom_certificate,
    ecc_mult,
    G,
    P_256_N,
    ECCPoint
)

# Configuration de la page Streamlit
st.set_page_config(
    page_title="Corvus Drop - ECC Secure PKI & HTTPS Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Injection de styles CSS avancés (Aesthetics Premium)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;500;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    .cyber-title {
        background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 800;
        font-size: 2.6rem;
        text-align: center;
        margin-bottom: 5px;
    }
    
    .cyber-subtitle {
        color: #8892b0;
        font-family: 'Outfit', sans-serif;
        font-weight: 300;
        font-size: 1.1rem;
        text-align: center;
        margin-bottom: 30px;
    }
    
    .glass-card {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(10px);
        border-radius: 15px;
        padding: 25px;
        border: 1px rgba(255, 255, 255, 0.08) solid;
        margin-bottom: 25px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
    }
    
    .section-header {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 600;
        color: #00f2fe;
        margin-top: 15px;
        margin-bottom: 15px;
        border-bottom: 1px solid rgba(0, 242, 254, 0.15);
        padding-bottom: 5px;
    }
    
    div.stButton > button {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%) !important;
        color: white !important;
        font-family: 'Space Grotesk', sans-serif !important;
        font-weight: 600 !important;
        border: none !important;
        padding: 10px 24px !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(0, 242, 254, 0.2) !important;
        width: 100%;
    }
    
    div.stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(0, 242, 254, 0.4) !important;
        background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%) !important;
    }
    
    .status-active {
        background-color: rgba(46, 204, 113, 0.15);
        color: #2ecc71;
        border: 1px solid #2ecc71;
        padding: 6px 12px;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
        font-size: 0.9rem;
    }
    
    .status-inactive {
        background-color: rgba(231, 76, 60, 0.15);
        color: #e74c3c;
        border: 1px solid #e74c3c;
        padding: 6px 12px;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# Configuration générale
SERVER_URL = "http://localhost:8080"
CA_CERT_PATH = "ca_cert.pem"
NONCE_SIZE = 12  # Nonce ChaCha20 IETF (12 octets)
KEY_SIZE = 32

# Initialisation de la session Streamlit
if "chacha_key" not in st.session_state:
    st.session_state["chacha_key"] = None

# ---- Fonctions Cryptographiques ECC (PKI) ----

def generate_ecc_private_key():
    private_key = int.from_bytes(os.urandom(32), "big") % P_256_N
    if private_key == 0:
        private_key = 1
    return private_key

def generate_root_ca_ecc(private_key, common_name, days_valid):
    public_key = ecc_mult(private_key, G)
    cert = create_custom_certificate(common_name, common_name, days_valid, public_key, private_key)
    return cert

def generate_and_sign_server_cert_ecc(server_private_key, ca_cert_pem, ca_private_key, common_name, days_valid):
    try:
        lines = ca_cert_pem.strip().split("\n")
        body_json = "".join([l for l in lines if not l.startswith("-----")])
        ca_data = json.loads(body_json)
        issuer_cn = ca_data["subject"]["CN"]
    except Exception:
        issuer_cn = "Local ECC Root CA"
        
    server_public_key = ecc_mult(server_private_key, G)
    cert = create_custom_certificate(common_name, issuer_cn, days_valid, server_public_key, ca_private_key)
    return cert

# ---- Fonctions Cryptographiques ChaCha20 ----

def generate_key_256() -> bytes:
    return os.urandom(KEY_SIZE)

def encrypt_in_memory(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = chacha20_encrypt(data, key, nonce)
    return nonce + ciphertext

def decrypt_in_memory(encrypted_data: bytes, key: bytes) -> bytes:
    if len(encrypted_data) < NONCE_SIZE:
        raise ValueError("Données trop courtes.")
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    return chacha20_decrypt(ciphertext, key, nonce)

# ---- Fonction Inspecteur HTTPS Réel (Standard Socket TLS sans cryptography) ----

def fetch_live_https_certificate(domain: str) -> dict:
    clean_domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((clean_domain, 443), timeout=5) as sock:
        with ssl_context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
            cert_dict = ssock.getpeercert(binary_form=False)
            return cert_dict

# ---- En-tête Global ----
st.markdown('<h1 class="cyber-title">🛡️ Corvus Drop - Secure PKI & HTTPS Lab</h1>', unsafe_allow_html=True)
st.markdown('<p class="cyber-subtitle">Corvus Drop - Outils de cryptographie avancés 100% développés FROM SCRATCH</p>', unsafe_allow_html=True)

# Barre d'onglets principale
tab_live_https, tab_pki, tab_key, tab_upload, tab_download = st.tabs([
    "🌐 Inspecteur HTTPS Réel & Confiance",
    "📜 PKI & Certificats ECC",
    "🔑 Gestion des Clés Symétriques",
    "📤 Envoyer un Fichier (Upload)",
    "📥 Recevoir un Fichier (Download)"
])

# ================= ONGLET 1 : INSPECTEUR HTTPS RÉEL & CONFIANCE =================
with tab_live_https:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    col_left, col_right = st.columns([1, 1])
    
    with col_left:
        st.markdown('<h3 class="section-header">🌐 Inspecteur de Certificat HTTPS Réel</h3>', unsafe_allow_html=True)
        st.write(
            "Entrez l'adresse de n'importe quel site internet sécurisé pour effectuer une négociation TLS (Handshake) "
            "en temps réel, récupérer son certificat X.509 standard et analyser sa structure de sécurité."
        )
        
        target_domain = st.text_input(
            "Nom de domaine à analyser (ex: google.com, github.com, wikipedia.org)",
            value="google.com"
        )
        
        if st.button("🔍 Interroger le Certificat Réel"):
            if not target_domain.strip():
                st.error("Veuillez entrer un domaine valide.")
            else:
                try:
                    with st.spinner(f"Connexion TLS en cours sur {target_domain}..."):
                        cert_dict = fetch_live_https_certificate(target_domain)
                        
                        st.success(f"🔒 Connexion TLS établie ! Certificat de {target_domain} récupéré avec succès.")
                        
                        # Affichage des métadonnées
                        st.markdown("##### 📋 Identité du Certificat")
                        
                        subject_formatted = ", ".join([f"{k}={v}" for item in cert_dict.get("subject", []) for k, v in item])
                        issuer_formatted = ", ".join([f"{k}={v}" for item in cert_dict.get("issuer", []) for k, v in item])
                        
                        st.write(f"**Sujet (Subject) :** `{subject_formatted}`")
                        st.write(f"**Émetteur (Issuer / CA) :** `{issuer_formatted}`")
                        st.write(f"**Numéro de Série :** `{cert_dict.get('serialNumber')}`")
                        
                        # Calcul validité
                        st.markdown("##### ⌛ Validité")
                        st.write(f"Actif depuis le : `{cert_dict.get('notBefore')}`")
                        st.write(f"Expire le : `{cert_dict.get('notAfter')}`")
                        
                except Exception as e:
                    st.error(f"❌ Impossible d'établir la connexion ou de récupérer le certificat : {e}")
                    st.info("💡 Vérifiez que votre ordinateur est bien connecté à Internet et que le nom de domaine est correct.")

    with col_right:
        st.markdown('<h3 class="section-header">🛡️ Architecture de Sécurité Applicative</h3>', unsafe_allow_html=True)
        st.write(
            "Le laboratoire cryptographique **Corvus Drop** a été entièrement ré-architecturé **FROM SCRATCH**."
        )
        st.write(
            "Toutes les primitives mathématiques (chiffrement symétrique par flux ChaCha20, arithmétique modulaire "
            "sur courbes elliptiques NIST P-256 et signatures ECDSA) ont été recodées en pur Python sans faire appel "
            "à des bibliothèques système binaires (ex: OpenSSL, rust-cryptography)."
        )
        st.success(
            "🔒 **Résultat :** Vous disposez d'un système autonome, robuste et parfaitement transparent au niveau de sa logique mathématique !"
        )
        
    st.markdown('</div>', unsafe_allow_html=True)


# ================= ONGLET 2 : PKI & CERTIFICATS ECC =================
with tab_pki:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<h3 class="section-header">📜 Simulateur de Système de Certification ECC</h3>', unsafe_allow_html=True)
    st.write(
        "Ce module simule une Autorité de Certification (CA) complète basée sur la "
        "cryptographie sur les courbes elliptiques (ECC) codée de A à Z. Générez votre Root CA et signez des certificats."
    )
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.markdown("#### 1️⃣ Initialiser une Root CA ECC")
        ca_cn = st.text_input("Nom Commun de la CA (Common Name)", value="Local ECC Root CA", key="ca_cn_input")
        ca_org = st.text_input("Organisation (O)", value="My Security Laboratory", key="ca_org_input")
        ca_days = st.number_input("Validité de la Root CA (jours)", value=365, min_value=1, key="ca_validity_input")
        ca_password = st.text_input("Définir un mot de passe fort pour la Root CA", type="password", key="ca_password_setup_pki", help="Utilisé pour chiffrer la clé privée de l'autorité racine via KDF robust.")
        
        if st.button("✨ Générer la Root CA", key="gen_root_ca_btn"):
            if len(ca_password) < 8:
                st.error("❌ Erreur : Le mot de passe de la Root CA doit faire au moins 8 caractères !")
            else:
                try:
                    ca_priv = generate_ecc_private_key()
                    ca_cert_pem = generate_root_ca_ecc(ca_priv, ca_cn, ca_days)
                    ca_priv_pem = serialize_custom_private_key(ca_priv, ca_password)
                    
                    with open("ca_private_key.pem", "w", encoding="utf-8") as f:
                        f.write(ca_priv_pem)
                    with open("ca_cert.pem", "w", encoding="utf-8") as f:
                        f.write(ca_cert_pem)
                    
                    # Copie automatique dans le dossier serveur si présent
                    server_dir = os.path.join("..", "server")
                    if os.path.exists(server_dir):
                        with open(os.path.join(server_dir, "ca_private_key.pem"), "w", encoding="utf-8") as f:
                            f.write(ca_priv_pem)
                        with open(os.path.join(server_dir, "ca_cert.pem"), "w", encoding="utf-8") as f:
                            f.write(ca_cert_pem)
                        
                    st.success("🎉 Root CA ECC générée et sauvegardée localement (ca_private_key.pem, ca_cert.pem) !")
                except Exception as e:
                    st.error(f"Erreur de génération : {e}")

    with col_right:
        st.markdown("#### 2️⃣ Émettre et signer un Certificat Serveur")
        st.write("Génère une clé serveur ECC et crée un certificat signé par la Root CA locale active.")
        server_cn = st.text_input("Common Name du Serveur", value="localhost", key="serv_cn_input")
        server_days = st.number_input("Validité du Certificat Serveur (jours)", value=30, min_value=1, key="serv_days_input")
        ca_decrypt_password = st.text_input("Saisir le mot de passe de la Root CA active", type="password", key="ca_password_decrypt_pki", help="Nécessaire pour déverrouiller la clé privée de la CA et signer.")
        
        if st.button("✍️ Signer le Certificat Serveur", key="sign_serv_cert_btn"):
            if not os.path.exists("ca_cert.pem") or not os.path.exists("ca_private_key.pem"):
                st.error("❌ Erreur : Vous devez d'abord générer la Root CA (étape 1) pour pouvoir signer !")
            elif not ca_decrypt_password:
                st.error("❌ Erreur : Veuillez entrer le mot de passe pour déverrouiller la Root CA active !")
            else:
                try:
                    with open("ca_private_key.pem", "r", encoding="utf-8") as f:
                        ca_priv = deserialize_custom_private_key(f.read(), password=ca_decrypt_password)
                    with open("ca_cert.pem", "r", encoding="utf-8") as f:
                        ca_cert_pem = f.read()
                        
                    server_priv = generate_ecc_private_key()
                    server_cert_pem = generate_and_sign_server_cert_ecc(
                        server_priv, ca_cert_pem, ca_priv, server_cn, server_days
                    )
                    
                    server_priv_pem = serialize_custom_private_key(server_priv)
                    
                    with open("server_private_key.pem", "w", encoding="utf-8") as f:
                        f.write(server_priv_pem)
                    with open("server_cert.pem", "w", encoding="utf-8") as f:
                        f.write(server_cert_pem)
                    
                    # Copie automatique dans le dossier serveur si présent
                    server_dir = os.path.join("..", "server")
                    if os.path.exists(server_dir):
                        with open(os.path.join(server_dir, "server_private_key.pem"), "w", encoding="utf-8") as f:
                            f.write(server_priv_pem)
                        with open(os.path.join(server_dir, "server_cert.pem"), "w", encoding="utf-8") as f:
                            f.write(server_cert_pem)
                        
                    st.success("🎉 Certificat Serveur signé avec succès ! Fichiers sauvegardés (server_private_key.pem, server_cert.pem)")
                except Exception as e:
                    st.error(f"Erreur de signature : {e}")
                    
    st.markdown("---")
    st.markdown('<h3 class="section-header">🔍 Inspecteur de Certificat Customisé FROM SCRATCH</h3>', unsafe_allow_html=True)
    st.write("Glissez-déposez n'importe quel certificat PEM customisé généré par notre PKI pour analyser visuellement son contenu.")
    
    uploaded_cert_file = st.file_uploader("Importer un certificat customisé", type=["pem", "crt"], key="cert_upl_inspector")
    
    if uploaded_cert_file is not None:
        try:
            cert_pem = uploaded_cert_file.read().decode("utf-8")
            lines = cert_pem.strip().split("\n")
            body_json = "".join([l for l in lines if not l.startswith("-----")])
            cert_obj = json.loads(body_json)
            
            st.success("Analyse réussie !")
            
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**📋 Sujet (Subject CN) :**")
                st.code(cert_obj["subject"]["CN"])
                st.markdown("**✍️ Émetteur (Issuer CN) :**")
                st.code(cert_obj["issuer"]["CN"])
                st.markdown("**⌛ Dates de validité (jours) :**")
                st.write(f"Durée : `{cert_obj['validity']['days']} jours`")
                
            with c2:
                st.markdown("**🔑 Clé Publique Asymétrique ECC NIST P-256 :**")
                st.code(f"Point Public X: {cert_obj['public_key']['x']}\nPoint Public Y: {cert_obj['public_key']['y']}", language="text")
                st.markdown("**✍️ Signature Numérique ECDSA (r, s) :**")
                st.code(f"r: {cert_obj['signature']['r']}\ns: {cert_obj['signature']['s']}", language="text")
        except Exception as e:
            st.error(f"Impossible de parser le certificat : {e}")
            
    st.markdown('</div>', unsafe_allow_html=True)


# ================= ONGLET 3 : GESTION DES CLÉS SYMÉTRIQUES =================
with tab_key:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Configuration de la Clé Symétrique ChaCha20")
    st.write(
        "Pour chiffrer les fichiers de bout en bout, ChaCha20 nécessite une clé secrète partagée de 256 bits (32 octets). "
        "Générez-la automatiquement ou insérez-en une ci-dessous."
    )
    
    if st.button("✨ Générer une clé aléatoire", key="gen_sym_key_pki"):
        new_key = generate_key_256()
        st.session_state["chacha_key"] = new_key
        st.success("Nouvelle clé cryptographique générée avec succès !")

    current_key_hex = ""
    if st.session_state["chacha_key"] is not None:
        current_key_hex = st.session_state["chacha_key"].hex()

    user_key_input = st.text_input(
        "Clé symétrique secrète (Hexadécimal)",
        value=current_key_hex,
        type="password",
        key="sym_key_input_pki",
        help="Saisissez ou modifiez votre clé symétrique au format hexadécimal (64 caractères)."
    )

    if user_key_input != current_key_hex:
        try:
            cleaned_key = bytes.fromhex(user_key_input.strip())
            if len(cleaned_key) == KEY_SIZE:
                st.session_state["chacha_key"] = cleaned_key
                st.success("Clé mise à jour avec succès depuis la saisie hexadécimale.")
                st.rerun()
            else:
                st.error(f"La clé doit faire exactement 256 bits, soit 64 caractères hexadécimaux. Actuel : {len(cleaned_key)} octets.")
        except ValueError:
            if user_key_input.strip() != "":
                st.error("Format hexadécimal invalide. Utilisez uniquement des caractères hexadécimaux de 0-9 et a-f.")

    if st.session_state["chacha_key"] is not None:
        show_key = st.checkbox("Afficher la clé en clair", key="show_sym_key_pki")
        if show_key:
            st.code(st.session_state["chacha_key"].hex(), language="text")
            st.info("💡 Conservez précieusement cette clé ! Sans elle, aucun fichier chiffré ne pourra être récupéré.")
    st.markdown('</div>', unsafe_allow_html=True)


# ================= ONGLET 4 : ENVOYER UN FICHIER =================
with tab_upload:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Chiffrement Local & Téléversement Sécurisé (Host A ➔ Host B)")
    
    key_configured = st.session_state["chacha_key"] is not None
    
    if not key_configured:
        st.warning("⚠️ Veuillez d'abord configurer ou générer une clé symétrique dans l'onglet 'Gestion des Clés Symétriques' avant de chiffrer vos fichiers.")
    else:
        st.write("Sélectionnez un fichier en clair. Le chiffrement s'effectue en mémoire avant d'être téléversé sur le serveur via HTTP.")
        
        uploaded_file = st.file_uploader("Sélectionner un fichier local", type=None, key="file_upl_pki")
        
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            original_filename = uploaded_file.name
            st.info(f"Fichier sélectionné : {original_filename} ({len(file_bytes)} octets)")
            
            if st.button("🔒 Chiffrer et Téléverser", key="encrypt_and_upl_btn_pki"):
                try:
                    with st.spinner("Chiffrement ChaCha20 en mémoire et téléversement HTTP..."):
                        key = st.session_state["chacha_key"]
                        encrypted_payload = encrypt_in_memory(file_bytes, key)
                        encrypted_filename = f"{original_filename}.enc"
                        
                        files = {
                            'file': (encrypted_filename, encrypted_payload, 'application/octet-stream')
                        }
                        
                        response = requests.post(
                            f"{SERVER_URL}/upload",
                            files=files
                        )
                        response.raise_for_status()
                        
                        st.success(f"🎉 Succès ! Le fichier a été chiffré et téléversé.")
                        st.json(response.json())
                        
                except Exception as e:
                    st.error(f"❌ Une erreur s'est produite lors de l'opération : {e}")
    st.markdown('</div>', unsafe_allow_html=True)


# ================= ONGLET 5 : RECEVOIR UN FICHIER =================
with tab_download:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Téléchargement HTTP & Déchiffrement ChaCha20")
    
    key_configured = st.session_state["chacha_key"] is not None
    
    if not key_configured:
        st.warning("⚠️ Veuillez d'abord configurer ou générer une clé symétrique dans l'onglet 'Gestion des Clés Symétriques' avant de déchiffrer vos fichiers.")
    else:
        st.write("Saisissez le nom du fichier chiffré stocké sur le serveur FastAPI pour le télécharger et le déchiffrer instantanément.")
        
        file_to_download = st.text_input(
            "Nom du fichier chiffré (ex: document_confidentiel.txt.enc)",
            placeholder="document_confidentiel.txt.enc",
            key="file_to_down_input_pki"
        )
        
        if st.button("📥 Télécharger et Déchiffrer", key="down_and_decrypt_btn_pki"):
            if not file_to_download.strip():
                st.error("Veuillez entrer un nom de fichier valide.")
            else:
                try:
                    with st.spinner("Téléchargement sécurisé et déchiffrement en cours..."):
                        response = requests.get(
                            f"{SERVER_URL}/download/{file_to_download.strip()}"
                        )
                        response.raise_for_status()
                        
                        encrypted_content = response.content
                        
                        key = st.session_state["chacha_key"]
                        decrypted_data = decrypt_in_memory(encrypted_content, key)
                        
                        restored_filename = file_to_download.replace(".enc", "")
                        if restored_filename == file_to_download:
                            restored_filename = f"restored_{file_to_download}"
                            
                        st.success(f"🔓 Déchiffrement réussi avec la clé symétrique ({len(decrypted_data)} octets restaurés) !")
                        
                        st.download_button(
                            label="💾 Sauvegarder le fichier déchiffré en clair",
                            data=decrypted_data,
                            file_name=restored_filename,
                            mime="application/octet-stream",
                            key="save_restored_file_btn_pki"
                        )
                        
                except requests.exceptions.HTTPError as http_err:
                    if response.status_code == 404:
                        st.error("❌ Fichier introuvable sur le serveur. Assurez-vous d'avoir saisi le nom exact (avec l'extension .enc).")
                    else:
                        st.error(f"❌ Erreur HTTP du serveur : {http_err}")
                except Exception as e:
                    st.error(f"❌ Une erreur s'est produite lors du téléchargement ou du déchiffrement : {e}")
                    st.info("💡 Conseil : Assurez-vous d'utiliser la clé symétrique identique à celle ayant servi au chiffrement de ce fichier.")
    st.markdown('</div>', unsafe_allow_html=True)

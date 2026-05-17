#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système d'Échange de Fichiers Sécurisé - Interface Graphique Premium avec PKI ECC & Inspecteur HTTPS Réel
====================================================================================================

Cette interface centralisée propose :
1. Un inspecteur HTTPS réel pour n'importe quel site internet (TLS Handshake & Analyse X.509).
2. Un guide et outil d'intégration pour un "Vrai HTTPS" local sans avertissement de sécurité.
3. Un simulateur de PKI asymétrique ECC (Root CA, CSR, signature de certificats).
4. La gestion de clé symétrique ChaCha20 et l'envoi/réception de fichiers chiffrés par API HTTPS.

Auteur: Ingénieur Sécurité & Cryptographie
"""

import os
import ipaddress
import datetime
import socket
import ssl
import requests
import streamlit as st
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

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
SERVER_URL = "https://localhost:8443"
CA_CERT_PATH = "ca_cert.pem"
NONCE_SIZE = 16
KEY_SIZE = 32

# Initialisation de la session Streamlit
if "chacha_key" not in st.session_state:
    st.session_state["chacha_key"] = None

# ---- Fonctions Cryptographiques ECC (PKI) ----

def get_curve_by_name(name: str):
    curves = {
        "SECP384R1 (NIST P-384)": ec.SECP384R1(),
        "SECP256R1 (NIST P-256)": ec.SECP256R1(),
        "SECP521R1 (NIST P-521)": ec.SECP521R1()
    }
    return curves.get(name, ec.SECP384R1())


def generate_ecc_private_key(curve):
    return ec.generate_private_key(curve)


def generate_root_ca_ecc(private_key, country, state, locality, org, common_name, days_valid):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, hashes.SHA384())
    )
    return cert


def generate_and_sign_server_cert_ecc(
    server_private_key, ca_cert, ca_private_key, common_name, days_valid
):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "IDF"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Exchange Co"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    
    san_list = [x509.DNSName("localhost")]
    try:
        ip_addr = ipaddress.ip_address(common_name)
        san_list.append(x509.IPAddress(ip_addr))
    except ValueError:
        if common_name != "localhost":
            san_list.append(x509.DNSName(common_name))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .sign(ca_private_key, hashes.SHA384())
    )
    return cert

# ---- Fonctions Cryptographiques ChaCha20 ----

def generate_key_256() -> bytes:
    return os.urandom(KEY_SIZE)


def encrypt_in_memory(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    algorithm = algorithms.ChaCha20(key, nonce)
    encryptor = Cipher(algorithm, mode=None).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce + ciphertext


def decrypt_in_memory(encrypted_data: bytes, key: bytes) -> bytes:
    if len(encrypted_data) < NONCE_SIZE:
        raise ValueError("Données trop courtes.")
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    algorithm = algorithms.ChaCha20(key, nonce)
    decryptor = Cipher(algorithm, mode=None).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---- Fonction Inspecteur HTTPS Réel (TLS socket connection) ----

def fetch_live_https_certificate(domain: str):
    """
    Se connecte à un domaine distant sur le port 443 via TLS
    et récupère le certificat HTTPS actif sous forme d'objet cryptography.
    """
    clean_domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    
    # Configuration du contexte SSL standard pour récupérer le certificat distant
    ssl_context = ssl.create_default_context()
    
    # On n'impose pas la validation de CA sur notre inspecteur pour lui permettre de lire également 
    # des certificats auto-signés ou expirés afin que l'utilisateur puisse les analyser !
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((clean_domain, 443), timeout=5) as sock:
        with ssl_context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            return x509.load_der_x509_certificate(der_cert)


# ---- En-tête Global ----
st.markdown('<h1 class="cyber-title">🛡️ Corvus Drop - Secure PKI & HTTPS Lab</h1>', unsafe_allow_html=True)
st.markdown('<p class="cyber-subtitle">Corvus Drop - Analyseur HTTPS Réel, Simulateur PKI ECC & Chiffrement ChaCha20</p>', unsafe_allow_html=True)

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
            "en temps réel, récupérer son certificat de sécurité X.509 officiel et l'analyser cryptographiquement."
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
                        cert = fetch_live_https_certificate(target_domain)
                        
                        st.success(f"🔒 Connexion TLS établie ! Certificat de {target_domain} récupéré avec succès.")
                        
                        # Affichage des métadonnées
                        st.markdown("##### 📋 Identité du Certificat")
                        st.write(f"**Sujet (Subject) :** `{cert.subject.rfc4514_string()}`")
                        st.write(f"**Émetteur (Issuer / CA) :** `{cert.issuer.rfc4514_string()}`")
                        st.write(f"**Numéro de Série :** `{cert.serial_number}`")
                        
                        # Calcul validité
                        now_utc = datetime.datetime.now(datetime.timezone.utc)
                        valid_from = cert.not_valid_before_utc
                        valid_to = cert.not_valid_after_utc
                        days_left = (valid_to - now_utc).days
                        
                        st.markdown("##### ⌛ Validité")
                        st.write(f"Actif depuis le : `{valid_from}`")
                        st.write(f"Expire le : `{valid_to}`")
                        
                        if days_left > 0:
                            st.info(f"🟢 Certificat valide pour encore **{days_left} jours**.")
                        else:
                            st.error(f"🔴 Certificat EXPIRÉ depuis {-days_left} jours !")
                            
                        # Clé publique
                        pub_key = cert.public_key()
                        st.markdown("##### 🔑 Clé Publique Asymétrique")
                        if isinstance(pub_key, ec.EllipticCurvePublicKey):
                            st.success(f"Courbe Elliptique (ECC) : `{pub_key.curve.name}` ({pub_key.key_size} bits)")
                            numbers = pub_key.public_numbers()
                            st.code(f"Point Public X: {hex(numbers.x)}\nPoint Public Y: {hex(numbers.y)}", language="text")
                        elif hasattr(pub_key, "n"):  # RSA
                            st.warning(f"Algorithme Classique : RSA ({pub_key.key_size} bits)")
                            st.code(f"Modulus (N): {hex(pub_key.public_numbers().n)[:120]}...", language="text")
                        else:
                            st.write(f"Type de clé inconnu : {type(pub_key)}")
                            
                        # Signature
                        st.markdown("##### ✍️ Signature Numérique")
                        st.write(f"Algorithme de hachage de signature : `{cert.signature_hash_algorithm.name}`")
                        st.code(f"Signature hex : {cert.signature.hex()[:80]}...", language="text")
                        
                except Exception as e:
                    st.error(f"❌ Impossible d'établir la connexion ou de récupérer le certificat : {e}")
                    st.info("💡 Vérifiez que votre ordinateur est bien connecté à Internet et que le nom de domaine est correct.")

    with col_right:
        st.markdown('<h3 class="section-header">🛡️ Comment obtenir un \"Vrai HTTPS\" local sans avertissement ?</h3>', unsafe_allow_html=True)
        st.write(
            "Lorsque vous visitez `https://localhost:8443` sur votre navigateur, une alerte rouge de sécurité s'affiche. "
            "C'est parce que votre système d'exploitation ne connaît pas votre **Root CA locale** personnalisée (votre ancre de confiance)."
        )
        st.write(
            "Pour avoir un **Vrai HTTPS sécurisé (cadenas vert) localement**, vous devez importer le certificat "
            "de votre Root CA dans le magasin d'autorités de certification de confiance de votre système."
        )
        
        st.markdown("##### 💻 Méthode Windows automatique (PowerShell en un clic) :")
        st.write("Exécutez cette commande simple dans un terminal PowerShell lancé **en tant qu'Administrateur** :")
        
        st.code(
            f'Import-Certificate -FilePath "{os.path.abspath(CA_CERT_PATH)}" -CertStoreLocation Cert:\\LocalMachine\\Root',
            language="powershell"
        )
        
        st.markdown("##### 🦊 Méthode pour Mozilla Firefox :")
        st.write(
            "Firefox n'utilise pas le magasin Windows. Pour l'ajouter sur Firefox :\n"
            "1. Allez dans **Paramètres** -> **Vie privée et sécurité**.\n"
            "2. Faites défiler tout en bas et cliquez sur **Afficher les certificats**.\n"
            "3. Dans l'onglet **Autorités**, cliquez sur **Importer**.\n"
            "4. Sélectionnez le fichier `ca_cert.pem` et cochez la case *'Confirmer cette CA pour identifier des sites web'*."
        )
        
        st.markdown("##### 🔒 Résultat :")
        st.success(
            "Une fois le certificat importé, relancez votre navigateur et allez sur `https://localhost:8443/download/test` : "
            "l'avertissement aura complètement disparu et vous aurez un **cadenas vert sécurisé parfait**, identique à un site professionnel !"
        )
        
    st.markdown('</div>', unsafe_allow_html=True)


# ================= ONGLET 2 : PKI & CERTIFICATS ECC =================
with tab_pki:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<h3 class="section-header">📜 Simulateur de Système de Certification ECC</h3>', unsafe_allow_html=True)
    st.write(
        "Ce module simule une Autorité de Certification (CA) complète basée sur la "
        "cryptographie sur les courbes elliptiques (ECC). Générez votre Root CA et signez des certificats."
    )
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.markdown("#### 1️⃣ Initialiser une Root CA ECC")
        curve_name = st.selectbox(
            "Choisir la courbe Elliptique (ECC)",
            ["SECP384R1 (NIST P-384)", "SECP256R1 (NIST P-256)", "SECP521R1 (NIST P-521)"],
            key="curve_choice_pki"
        )
        ca_cn = st.text_input("Nom Commun de la CA (Common Name)", value="Local ECC Root CA", key="ca_cn_input")
        ca_org = st.text_input("Organisation (O)", value="My Security Laboratory", key="ca_org_input")
        ca_country = st.text_input("Pays (C)", value="FR", max_chars=2, key="ca_c_input")
        ca_days = st.number_input("Validité de la Root CA (jours)", value=365, min_value=1, key="ca_validity_input")
        ca_password = st.text_input("Définir un mot de passe fort pour la Root CA", type="password", key="ca_password_setup_pki", help="Utilisé pour chiffrer la clé privée de l'autorité racine via KDF.")
        
        if st.button("✨ Générer la Root CA", key="gen_root_ca_btn"):
            if len(ca_password) < 8:
                st.error("❌ Erreur : Le mot de passe de la Root CA doit faire au moins 8 caractères pour être sécurisé via KDF !")
            else:
                try:
                    selected_curve = get_curve_by_name(curve_name)
                    ca_priv = generate_ecc_private_key(selected_curve)
                    ca_cert = generate_root_ca_ecc(
                        ca_priv, ca_country, "IDF", "Paris", ca_org, ca_cn, ca_days
                    )
                    
                    password_bytes = ca_password.encode("utf-8")
                    ca_priv_pem = ca_priv.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
                    )
                ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
                
                with open("ca_private_key.pem", "wb") as f:
                    f.write(ca_priv_pem)
                with open("ca_cert.pem", "wb") as f:
                    f.write(ca_cert_pem)
                
                # Copie automatique dans le dossier serveur si présent
                server_dir = os.path.join("..", "server")
                if os.path.exists(server_dir):
                    with open(os.path.join(server_dir, "ca_private_key.pem"), "wb") as f:
                        f.write(ca_priv_pem)
                    with open(os.path.join(server_dir, "ca_cert.pem"), "wb") as f:
                        f.write(ca_cert_pem)
                    
                st.success("🎉 Root CA ECC générée et sauvegardée localement (ca_private_key.pem, ca_cert.pem) !")
            except Exception as e:
                st.error(f"Erreur de génération : {e}")

    with col_right:
        st.markdown("#### 2️⃣ Émettre et signer un Certificat Serveur")
        st.write("Génère une clé serveur ECC et crée un certificat signé par la Root CA locale active.")
        server_cn = st.text_input("Common Name du Serveur (ex: localhost ou 127.0.0.1)", value="localhost", key="serv_cn_input")
        server_days = st.number_input("Validité du Certificat Serveur (jours)", value=30, min_value=1, key="serv_days_input")
        ca_decrypt_password = st.text_input("Saisir le mot de passe de la Root CA active", type="password", key="ca_password_decrypt_pki", help="Nécessaire pour déverrouiller la clé privée de la CA et signer le certificat serveur.")
        
        if st.button("✍️ Signer le Certificat Serveur", key="sign_serv_cert_btn"):
            if not os.path.exists("ca_cert.pem") or not os.path.exists("ca_private_key.pem"):
                st.error("❌ Erreur : Vous devez d'abord générer la Root CA (étape 1) pour pouvoir signer !")
            elif not ca_decrypt_password:
                st.error("❌ Erreur : Veuillez entrer le mot de passe pour déverrouiller la Root CA active !")
            else:
                try:
                    with open("ca_private_key.pem", "rb") as f:
                        password_bytes = ca_decrypt_password.encode("utf-8")
                        ca_priv = serialization.load_pem_private_key(f.read(), password=password_bytes)
                    with open("ca_cert.pem", "rb") as f:
                        ca_cert = x509.load_pem_x509_certificate(f.read())
                        
                    curve_object = ca_priv.curve
                    server_priv = generate_ecc_private_key(curve_object)
                    
                    server_cert = generate_and_sign_server_cert_ecc(
                        server_priv, ca_cert, ca_priv, server_cn, server_days
                    )
                    
                    server_priv_pem = server_priv.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
                    
                    with open("server_private_key.pem", "wb") as f:
                        f.write(server_priv_pem)
                    with open("server_cert.pem", "wb") as f:
                        f.write(server_cert_pem)
                    
                    # Copie automatique dans le dossier serveur si présent
                    server_dir = os.path.join("..", "server")
                    if os.path.exists(server_dir):
                        with open(os.path.join(server_dir, "server_private_key.pem"), "wb") as f:
                            f.write(server_priv_pem)
                        with open(os.path.join(server_dir, "server_cert.pem"), "wb") as f:
                            f.write(server_cert_pem)
                        
                    st.success("🎉 Certificat Serveur signé avec succès ! Fichiers sauvegardés (server_private_key.pem, server_cert.pem)")
                except Exception as e:
                    st.error(f"Erreur de signature : {e}")
                    
    st.markdown("---")
    st.markdown('<h3 class="section-header">🔍 Inspecteur de Certificat X.509</h3>', unsafe_allow_html=True)
    st.write("Glissez-déposez n'importe quel certificat PEM (.pem ou .crt) pour analyser visuellement son contenu cryptographique.")
    
    uploaded_cert_file = st.file_uploader("Importer un certificat X.509", type=["pem", "crt", "der"], key="cert_upl_inspector")
    
    if uploaded_cert_file is not None:
        try:
            cert_data = uploaded_cert_file.read()
            cert_obj = x509.load_pem_x509_certificate(cert_data)
            
            st.success("Analyse réussie !")
            
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**📋 Sujet (Subject) :**")
                st.code(str(cert_obj.subject))
                st.markdown("**✍️ Émetteur (Issuer) :**")
                st.code(str(cert_obj.issuer))
                st.markdown("**🔢 Numéro de série :**")
                st.code(str(cert_obj.serial_number))
                st.markdown("**⌛ Dates de validité :**")
                st.write(f"Début : `{cert_obj.not_valid_before_utc}`")
                st.write(f"Fin : `{cert_obj.not_valid_after_utc}`")
                
            with c2:
                pub_key = cert_obj.public_key()
                st.markdown("**🔑 Clé Publique Asymétrique :**")
                if isinstance(pub_key, ec.EllipticCurvePublicKey):
                    st.info(f"🟢 Type : Courbe Elliptique (ECC)")
                    st.write(f"Nom de la courbe : `{pub_key.curve.name}`")
                    st.write(f"Taille de la clé : `{pub_key.key_size} bits`")
                    st.markdown("**📍 Coordonnées du Point Public (X, Y) :**")
                    numbers = pub_key.public_numbers()
                    st.code(f"X: {hex(numbers.x)}\nY: {hex(numbers.y)}", language="text")
                else:
                    st.warning("Type : RSA ou autre algorithme non-ECC")
                    st.write(f"Taille de la clé : `{pub_key.key_size} bits`")
                    
                st.markdown("**🛡️ Signature du Certificat :**")
                st.write(f"Algorithme de hachage : `{cert_obj.signature_hash_algorithm.name}`")
                st.code(f"Signature hex : {cert_obj.signature.hex()[:100]}...", language="text")
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
        st.write("Sélectionnez un fichier en clair. Le chiffrement s'effectue en mémoire avant d'être téléversé sur le serveur via HTTPS.")
        
        uploaded_file = st.file_uploader("Sélectionner un fichier local", type=None, key="file_upl_pki")
        
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            original_filename = uploaded_file.name
            st.info(f"Fichier sélectionné : {original_filename} ({len(file_bytes)} octets)")
            
            if st.button("🔒 Chiffrer et Téléverser", key="encrypt_and_upl_btn_pki"):
                try:
                    with st.spinner("Chiffrement ChaCha20 en mémoire et téléversement HTTPS..."):
                        key = st.session_state["chacha_key"]
                        encrypted_payload = encrypt_in_memory(file_bytes, key)
                        encrypted_filename = f"{original_filename}.enc"
                        
                        files = {
                            'file': (encrypted_filename, encrypted_payload, 'application/octet-stream')
                        }
                        
                        response = requests.post(
                            f"{SERVER_URL}/upload",
                            files=files,
                            verify=CA_CERT_PATH
                        )
                        response.raise_for_status()
                        
                        st.success(f"🎉 Succès ! Le fichier a été chiffré et téléversé.")
                        st.json(response.json())
                        
                except requests.exceptions.SSLError as ssl_err:
                    st.error("❌ Erreur TLS/SSL : Impossible de valider l'identité du serveur.")
                    st.write(f"Détail : {ssl_err}")
                except Exception as e:
                    st.error(f"❌ Une erreur s'est produite lors de l'opération : {e}")
    st.markdown('</div>', unsafe_allow_html=True)


# ================= ONGLET 5 : RECEVOIR UN FICHIER =================
with tab_download:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Téléchargement HTTPS & Déchiffrement ChaCha20")
    
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
                            f"{SERVER_URL}/download/{file_to_download.strip()}",
                            verify=CA_CERT_PATH
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

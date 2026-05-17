#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système d'Échange de Fichiers Sécurisé - Serveur Web HTTPS Premium (Host B)
========================================================================

Ce script met en place un serveur API et un portail d'administration HTTPS complet
en utilisant FastAPI et Uvicorn. Il intègre une interface web d'administration 
Premium, moderne et interactive sur le thème de la cybersécurité.

Auteur: Ingénieur Sécurité & Cryptographie - EMSI RS
"""

import os
import shutil
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
import uvicorn

app = FastAPI(
    title="Corvus Drop - Secure File Vault Server",
    description="Serveur d'échange de fichiers sécurisés via HTTPS (TLS)",
    version="1.0.0",
    docs_url=None  # Désactiver l'interface par défaut pour injecter la nôtre
)

# Répertoire de stockage des fichiers téléversés sur le serveur
STORAGE_DIR = "server_storage"
os.makedirs(STORAGE_DIR, exist_ok=True)


# ---- 1. PORTAIL WEB DASHBOARD PREMIUM (FRONTEND ROOT) ----

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """
    Sert l'interface utilisateur web principale (Dashboard Premium) du serveur.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🛡️ Corvus Drop - Secure Storage Vault</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
        <style>
            body {
                background-color: #0b0f19;
                color: #e2e8f0;
                font-family: 'Outfit', sans-serif;
                margin: 0;
                padding: 0;
            }

            /* Header Cyber */
            header {
                background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                border-bottom: 3px solid #00f2fe;
                padding: 20px;
                text-align: center;
                box-shadow: 0 4px 30px rgba(0, 242, 254, 0.15);
            }
            header h1 {
                font-family: 'Space Grotesk', sans-serif;
                color: #00f2fe;
                margin: 0;
                font-size: 2.2rem;
                font-weight: 700;
                text-shadow: 0 0 15px rgba(0, 242, 254, 0.4);
            }
            header p {
                color: #94a3b8;
                margin: 5px 0 0 0;
                font-size: 1rem;
            }

            .container {
                max-width: 1200px;
                margin: 40px auto;
                padding: 0 20px;
            }

            .grid {
                display: grid;
                grid-template-columns: 1fr 2fr;
                gap: 30px;
            }

            /* Widgets & Cards (Glassmorphism) */
            .card {
                background: rgba(30, 41, 59, 0.4);
                backdrop-filter: blur(10px);
                border-radius: 16px;
                border: 1px solid rgba(255, 255, 255, 0.08);
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                transition: all 0.3s ease;
            }
            .card:hover {
                border-color: rgba(0, 242, 254, 0.3);
                box-shadow: 0 10px 35px rgba(0, 242, 254, 0.1);
            }

            .card-title {
                font-family: 'Space Grotesk', sans-serif;
                color: #00f2fe;
                font-size: 1.4rem;
                margin-top: 0;
                margin-bottom: 20px;
                border-bottom: 1px solid rgba(0, 242, 254, 0.15);
                padding-bottom: 8px;
                display: flex;
                align-items: center;
                gap: 10px;
            }

            /* Status Indicator */
            .status-badge {
                display: inline-flex;
                align-items: center;
                background-color: rgba(16, 185, 129, 0.15);
                color: #10b981;
                border: 1px solid #10b981;
                padding: 6px 16px;
                border-radius: 30px;
                font-weight: 600;
                font-size: 0.9rem;
                gap: 8px;
            }
            .status-dot {
                width: 10px;
                height: 10px;
                background-color: #10b981;
                border-radius: 50%;
                box-shadow: 0 0 10px #10b981;
                animation: pulse 1.5s infinite alternate;
            }
            @keyframes pulse {
                from { transform: scale(0.9); opacity: 0.6; }
                to { transform: scale(1.15); opacity: 1; }
            }

            /* Zone d'Upload par Drag-and-Drop */
            .upload-zone {
                border: 2px dashed rgba(0, 242, 254, 0.3);
                border-radius: 12px;
                padding: 40px 20px;
                text-align: center;
                background: rgba(15, 23, 42, 0.6);
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .upload-zone * {
                pointer-events: none;
            }
            .upload-zone:hover {
                border-color: #00f2fe;
                background: rgba(0, 242, 254, 0.05);
            }
            .upload-zone p {
                margin: 10px 0 0 0;
                color: #94a3b8;
            }
            .upload-icon {
                font-size: 3rem;
                color: #00f2fe;
            }
            #fileInput {
                display: none;
            }

            /* Tables & Explorer */
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            th, td {
                text-align: left;
                padding: 14px 16px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }
            th {
                color: #94a3b8;
                font-weight: 600;
                font-family: 'Space Grotesk', sans-serif;
            }
            tr:hover td {
                background: rgba(255, 255, 255, 0.02);
            }

            /* Boutons Cyber */
            .btn {
                background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                color: #0b0f19;
                font-family: 'Space Grotesk', sans-serif;
                font-weight: 700;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.25s ease;
                display: inline-flex;
                align-items: center;
                gap: 6px;
                text-decoration: none;
                font-size: 0.9rem;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0, 242, 254, 0.4);
            }
            
            .btn-danger {
                background: rgba(239, 68, 68, 0.15);
                border: 1px solid #ef4444;
                color: #ef4444;
            }
            .btn-danger:hover {
                background: #ef4444;
                color: white;
                box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4);
            }

            .btn-docs {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.15);
                color: #e2e8f0;
                margin-top: 15px;
                width: 100%;
                box-sizing: border-box;
                justify-content: center;
            }
            .btn-docs:hover {
                border-color: #00f2fe;
                color: #00f2fe;
                box-shadow: none;
            }

            /* Notifications */
            .notification {
                padding: 12px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                display: none;
                font-weight: 600;
            }
            .notif-success {
                background-color: rgba(16, 185, 129, 0.15);
                color: #10b981;
                border: 1px solid #10b981;
            }
            .notif-error {
                background-color: rgba(239, 68, 68, 0.15);
                color: #ef4444;
                border: 1px solid #ef4444;
            }
        </style>
    </head>
    <body>
        <header>
            <h1>🛡️ CORVUS DROP - SECURE STORAGE VAULT</h1>
            <p>Portail de stockage chiffré de bout en bout sécurisé par TLS asymétrique ECC</p>
        </header>

        <div class="container">
            <div class="grid">
                <!-- COLONNE GAUCHE : ETAT SERVEUR & UPLOAD -->
                <div>
                    <!-- Carte 1 : Statut du Serveur -->
                    <div class="card" style="margin-bottom: 30px;">
                        <h2 class="card-title">🔌 Connexion & Sécurité</h2>
                        <div style="margin-bottom: 20px;">
                            <span class="status-badge">
                                <span class="status-dot"></span> HTTPS ACTIF
                            </span>
                        </div>
                        <div style="font-size: 0.95rem; line-height: 1.6;">
                            <p><strong>Autorité (CA) :</strong> <code style="color: #00f2fe;">EMSI RS</code></p>
                            <p><strong>Cryptographie :</strong> <code style="color: #00f2fe;">ECC SECP384R1</code></p>
                            <p><strong>Validation Client :</strong> Certificat Système OK</p>
                        </div>
                        
                        <!-- Lien vers la doc API Swagger -->
                        <a href="/docs" target="_blank" class="btn btn-docs">
                            📚 Ouvrir le portail API Swagger UI
                        </a>
                    </div>

                    <!-- Carte 2 : Zone d'Upload -->
                    <div class="card">
                        <h2 class="card-title">📤 Téléverser un Fichier</h2>
                        <div id="dropZone" class="upload-zone">
                            <div class="upload-icon">📁</div>
                            <p><strong>Glissez-déposez un fichier</strong></p>
                            <p style="font-size: 0.85rem; margin-top: 5px;">ou cliquez pour parcourir</p>
                            <input type="file" id="fileInput">
                        </div>
                    </div>
                </div>

                <!-- COLONNE DROITE : EXPLORATEUR DE FICHIERS -->
                <div class="card">
                    <h2 class="card-title" style="justify-content: space-between;">
                        <span>🗂️ Fichiers Chiffrés stockés sur le serveur</span>
                        <button onclick="fetchFiles()" class="btn" style="padding: 6px 12px; font-size: 0.8rem;">🔄 Actualiser</button>
                    </h2>
                    
                    <div id="notification" class="notification"></div>

                    <div style="overflow-x: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Nom du fichier chiffré</th>
                                    <th>Taille</th>
                                    <th style="text-align: right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="filesTableBody">
                                <!-- Les fichiers seront injectés ici dynamiquement -->
                                <tr>
                                    <td colspan="3" style="text-align: center; color: #94a3b8; padding: 30px 0;">
                                        Chargement de l'inventaire en cours...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // Récupère l'inventaire des fichiers stockés
            async function fetchFiles() {
                const tbody = document.getElementById('filesTableBody');
                try {
                    const response = await fetch('/api/files');
                    if (!response.ok) throw new Error("Impossible de lire l'inventaire.");
                    const files = await response.json();
                    
                    if (files.length === 0) {
                        tbody.innerHTML = `
                            <tr>
                                <td colspan="3" style="text-align: center; color: #94a3b8; padding: 40px 0;">
                                    🕳️ Aucun fichier stocké pour le moment sur le serveur.
                                </td>
                            </tr>
                        `;
                        return;
                    }

                    tbody.innerHTML = '';
                    files.forEach(file => {
                        const sizeFormatted = formatBytes(file.size);
                        
                        // Création dynamique de la ligne TR pour éviter tout problème de guillemets
                        const tr = document.createElement('tr');
                        
                        tr.innerHTML = `
                            <td style="font-family: monospace; font-weight: 600;"></td>
                            <td>${sizeFormatted}</td>
                            <td style="text-align: right;">
                                <a class="btn" style="padding: 5px 12px; font-size: 0.8rem;">📥 Télécharger</a>
                            </td>
                        `;
                        
                        // Injection sécurisée du nom de fichier (XSS Safe & Space Safe)
                        tr.cells[0].textContent = file.name;
                        
                        // Configuration du bouton de téléchargement
                        const downloadBtn = tr.querySelector('a');
                        downloadBtn.href = `/download/${encodeURIComponent(file.name)}`;
                        
                        // Création du bouton de suppression
                        const deleteBtn = document.createElement('button');
                        deleteBtn.className = 'btn btn-danger';
                        deleteBtn.style.padding = '5px 12px';
                        deleteBtn.style.fontSize = '0.8rem';
                        deleteBtn.style.marginLeft = '5px';
                        deleteBtn.textContent = '🗑️ Supprimer';
                        
                        // Liaison de l'événement de suppression sans attribut inline HTML
                        deleteBtn.addEventListener('click', () => deleteFile(file.name));
                        
                        // Ajout du bouton à la colonne d'action
                        tr.cells[2].appendChild(deleteBtn);
                        
                        tbody.appendChild(tr);
                    });
                } catch (error) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="3" style="text-align: center; color: #ef4444; padding: 30px 0; font-weight: 600;">
                                ❌ Erreur de chargement : ${error.message}
                            </td>
                        </tr>
                    `;
                }
            }

            // Supprimer un fichier
            async function deleteFile(filename) {
                if(!confirm(`Voulez-vous vraiment supprimer le fichier ${filename} du serveur ?`)) return;
                try {
                    const response = await fetch(`/api/delete/${filename}`, { method: 'DELETE' });
                    if (!response.ok) throw new Error("Erreur lors de la suppression.");
                    showNotification("Fichier supprimé du serveur avec succès !", "success");
                    fetchFiles();
                } catch (error) {
                    showNotification(error.message, "error");
                }
            }

            // Empêcher le comportement par défaut du navigateur d'ouvrir les fichiers glissés hors zone
            window.addEventListener("dragover", function(e) {
                e.preventDefault();
            }, false);
            window.addEventListener("drop", function(e) {
                e.preventDefault();
            }, false);

            // Gestion de l'Upload via AJAX
            const dropZone = document.getElementById('dropZone');
            const fileInput = document.getElementById('fileInput');

            dropZone.onclick = () => fileInput.click();

            fileInput.onchange = (e) => {
                if (e.target.files.length > 0) {
                    uploadFile(e.target.files[0]);
                }
            };

            // Drag and Drop events
            dropZone.ondragover = (e) => {
                e.preventDefault();
                dropZone.style.borderColor = '#00f2fe';
                dropZone.style.background = 'rgba(0, 242, 254, 0.08)';
            };
            dropZone.ondragleave = () => {
                dropZone.style.borderColor = 'rgba(0, 242, 254, 0.3)';
                dropZone.style.background = 'rgba(15, 23, 42, 0.6)';
            };
            dropZone.ondrop = (e) => {
                e.preventDefault();
                dropZone.style.borderColor = 'rgba(0, 242, 254, 0.3)';
                dropZone.style.background = 'rgba(15, 23, 42, 0.6)';
                if (e.dataTransfer.files.length > 0) {
                    uploadFile(e.dataTransfer.files[0]);
                }
            };

            async function uploadFile(file) {
                const formData = new FormData();
                formData.append('file', file);
                
                showNotification("Téléversement sécurisé en cours...", "success");
                
                try {
                    const response = await fetch('/upload', {
                        method: 'POST',
                        body: formData
                    });
                    if(!response.ok) throw new Error("Téléversement échoué.");
                    showNotification(`🎉 Succès ! Le fichier "${file.name}" a été enregistré sur le serveur.`, "success");
                    fetchFiles();
                } catch (error) {
                    showNotification(error.message, "error");
                }
            }

            // Utilitaires
            function showNotification(text, type) {
                const notif = document.getElementById('notification');
                notif.style.display = 'block';
                notif.innerText = text;
                notif.className = 'notification ' + (type === "success" ? "notif-success" : "notif-error");
                setTimeout(() => { notif.style.display = 'none'; }, 5000);
            }

            function formatBytes(bytes, decimals = 2) {
                if (bytes === 0) return '0 Octets';
                const k = 1024;
                const dm = decimals < 0 ? 0 : decimals;
                const sizes = ['Octets', 'Ko', 'Mo', 'Go'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
            }

            // Chargement initial direct et robuste
            fetchFiles();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# ---- 2. SERVICES REST API (FASTAPI ENGINE) ----

@app.get("/api/files", summary="Lister les fichiers stockés sur le serveur")
async def list_files():
    """
    Renvoie la liste des noms et des tailles de tous les fichiers stockés dans le coffre.
    """
    try:
        files = []
        for filename in os.listdir(STORAGE_DIR):
            file_path = os.path.join(STORAGE_DIR, filename)
            if os.path.isfile(file_path):
                files.append({
                    "name": filename,
                    "size": os.path.getsize(file_path)
                })
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur d'exploration : {e}")


@app.delete("/api/delete/{filename}", summary="Supprimer un fichier du serveur")
async def delete_file(filename: str):
    """
    Supprime définitivement un fichier stocké sur le serveur de fichiers.
    """
    clean_filename = os.path.basename(filename)
    file_path = os.path.join(STORAGE_DIR, clean_filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Fichier introuvable.")

    try:
        os.remove(file_path)
        print(f"[-] Fichier supprimé : {clean_filename}")
        return {"status": "success", "message": f"Fichier {clean_filename} supprimé."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de suppression : {e}")


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """
    Génère une interface Swagger UI personnalisée sur le thème de la cybersécurité.
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
    <title>🛡️ Corvus Drop - Portal API</title>
    <style>
        body {
            background-color: #0b0f19 !important;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif !important;
        }
        
        /* En-tête Cyber Premium */
        .cyber-header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-bottom: 3px solid #00f2fe;
            padding: 25px 20px;
            text-align: center;
            box-shadow: 0 4px 30px rgba(0, 242, 254, 0.15);
        }
        .cyber-header h1 {
            color: #00f2fe;
            font-family: 'Space Grotesk', sans-serif;
            margin: 0;
            font-size: 2.1rem;
            font-weight: 700;
            letter-spacing: 1.5px;
            text-shadow: 0 0 15px rgba(0, 242, 254, 0.4);
        }
        .cyber-header p {
            color: #94a3b8;
            margin: 8px 0 0 0;
            font-size: 1rem;
            font-weight: 300;
        }

        /* Wrapper Général Swagger */
        .swagger-ui {
            background-color: #0b0f19 !important;
            color: #e2e8f0 !important;
            padding-bottom: 50px;
        }
        
        /* Modification des textes */
        .swagger-ui .info .title, 
        .swagger-ui .info li, 
        .swagger-ui .info p, 
        .swagger-ui .info td, 
        .swagger-ui .info a {
            color: #e2e8f0 !important;
        }
        
        .swagger-ui .info .title {
            font-family: 'Space Grotesk', sans-serif !important;
            color: #00f2fe !important;
            font-size: 2.3rem !important;
            font-weight: 700 !important;
            margin-top: 30px !important;
        }
        
        .swagger-ui .info .title small {
            background-color: #00f2fe !important;
            color: #0b0f19 !important;
            font-weight: bold !important;
            border-radius: 6px !important;
            padding: 4px 8px !important;
        }

        .swagger-ui .scheme-container {
            background-color: #111827 !important;
            box-shadow: none !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 12px !important;
            margin: 30px 0 !important;
            padding: 20px !important;
        }

        /* Boutons personnalisés avec effet de lueur */
        .swagger-ui .btn {
            background-color: #1f2937 !important;
            color: #00f2fe !important;
            border: 1px solid #00f2fe !important;
            border-radius: 8px !important;
            font-family: 'Space Grotesk', sans-serif !important;
            font-weight: 600 !important;
            transition: all 0.25s ease !important;
            box-shadow: 0 4px 10px rgba(0, 242, 254, 0.1) !important;
        }
        .swagger-ui .btn:hover {
            background-color: #00f2fe !important;
            color: #0b0f19 !important;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.5) !important;
            transform: translateY(-1px);
        }

        /* Boîtes d'Opération d'API */
        .swagger-ui .opblock {
            background-color: #111827 !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 12px !important;
            box-shadow: 0 6px 12px rgba(0,0,0,0.15) !important;
            margin-bottom: 20px !important;
            overflow: hidden !important;
        }
        
        .swagger-ui .opblock-summary {
            border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
            padding: 12px 20px !important;
        }

        .swagger-ui .opblock .opblock-summary-path {
            color: #f3f4f6 !important;
            font-weight: 600 !important;
            font-family: monospace !important;
            font-size: 1.1rem !important;
        }

        .swagger-ui .opblock .opblock-summary-description {
            color: #9ca3af !important;
            font-weight: 300 !important;
        }

        /* Couleur Spécifique POST */
        .swagger-ui .opblock.opblock-post {
            border-color: #10b981 !important;
            background-color: rgba(16, 185, 129, 0.03) !important;
        }
        .swagger-ui .opblock.opblock-post .opblock-summary-method {
            background-color: #10b981 !important;
            color: white !important;
            font-weight: bold !important;
            border-radius: 6px !important;
        }
        
        /* Couleur Spécifique GET */
        .swagger-ui .opblock.opblock-get {
            border-color: #3b82f6 !important;
            background-color: rgba(59, 130, 246, 0.03) !important;
        }
        .swagger-ui .opblock.opblock-get .opblock-summary-method {
            background-color: #3b82f6 !important;
            color: white !important;
            font-weight: bold !important;
            border-radius: 6px !important;
        }

        /* Conteneurs et formulaires internes */
        .swagger-ui .opblock .opblock-section-header {
            background-color: #1f2937 !important;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
            color: #00f2fe !important;
            font-family: 'Space Grotesk', sans-serif !important;
        }

        .swagger-ui table thead tr td, 
        .swagger-ui table thead tr th {
            color: #9ca3af !important;
            border-bottom: 2px solid rgba(255, 255, 255, 0.08) !important;
            font-weight: 600 !important;
        }

        .swagger-ui .response-col_status,
        .swagger-ui .response-col_links,
        .swagger-ui .parameter__name,
        .swagger-ui .parameter__type {
            color: #e5e7eb !important;
        }

        .swagger-ui textarea, 
        .swagger-ui input[type=text] {
            background-color: #1f2937 !important;
            color: white !important;
            border: 1px solid rgba(255, 255, 255, 0.15) !important;
            border-radius: 8px !important;
            padding: 8px !important;
        }

        .swagger-ui .model-box {
            background-color: #1f2937 !important;
            border-radius: 10px !important;
            border: 1px solid rgba(255, 255, 255, 0.06) !important;
            padding: 15px !important;
        }
        
        .swagger-ui .highlight-code {
            border-radius: 8px !important;
            overflow: hidden !important;
        }
    </style>
    </head>
    <body>
        <div class="cyber-header">
            <h1>🛡️ CORVUS DROP - SECURE FILE EXCHANGE API</h1>
            <p>Portail d'API cryptographique sécurisé de bout en bout par certificat ECC X.509</p>
        </div>
        <div id="swagger-ui"></div>
        <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
        <script>
            const ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                ],
                layout: "BaseLayout",
                deepLinking: true,
                docExpansion: "list"
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.post("/upload", summary="Téléversement d'un fichier chiffré")
async def upload_file(file: UploadFile = File(...)):
    """
    Reçoit un fichier et le stocke localement dans le répertoire sécurisé du serveur.
    """
    filename = os.path.basename(file.filename)
    dest_path = os.path.join(STORAGE_DIR, filename)

    print(f"[+] Réception du fichier : {filename}")

    try:
        with open(dest_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        return {
            "status": "success",
            "filename": filename,
            "message": "Fichier téléversé et stocké avec succès sur le serveur."
        }
    except Exception as e:
        print(f"[!] Erreur d'écriture fichier : {e}")
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {e}")


@app.get("/download/{filename}", summary="Téléchargement d'un fichier chiffré")
async def download_file(filename: str):
    """
    Renvoie le fichier chiffré demandé sous forme binaire.
    """
    clean_filename = os.path.basename(filename)
    file_path = os.path.join(STORAGE_DIR, clean_filename)

    if not os.path.exists(file_path):
        print(f"[!] Fichier non trouvé : {clean_filename}")
        raise HTTPException(status_code=404, detail="Fichier introuvable sur le serveur.")

    print(f"[+] Envoi du fichier : {clean_filename}")
    return FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=clean_filename
    )


if __name__ == "__main__":
    print("=" * 70)
    print("      SERVEUR SECURISE HTTPS ACTIF (PORT 8443)")
    print("=" * 70)

    # Configuration des chemins des certificats SSL/TLS
    cert_file = "server_cert.pem"
    key_file = "server_private_key.pem"

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"[!] ERREUR : Les certificats de test '{cert_file}' ou '{key_file}' sont introuvables.")
        print("    Veuillez d'abord exécuter 'python pki_setup.py' pour les générer.")
        exit(1)

    # Lancement d'Uvicorn avec support SSL natif
    uvicorn.run(
        "server:app",
        host="127.0.0.1",
        port=8443,
        ssl_keyfile=key_file,
        ssl_certfile=cert_file,
        reload=False
    )

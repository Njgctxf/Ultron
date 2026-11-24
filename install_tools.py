"""
install_tools.py - Autonomous Downloader & Installer for External Scanners
Downloads official native binaries for Nuclei, Trivy, Gitleaks, Sqlmap, and ffuf.

Usage:
    python install_tools.py
"""

import os
import sys
import shutil
import zipfile
import tarfile
import urllib.request
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent / "ultron" / "tools_bin"
IS_WINDOWS = os.name == "nt"

TOOL_RELEASES = {
    "nuclei": {
        "url_win": "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip",
        "url_linux": "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip",
        "binary": "nuclei.exe" if IS_WINDOWS else "nuclei"
    },
    "trivy": {
        "url_win": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Windows-64bit.zip",
        "url_linux": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz",
        "binary": "trivy.exe" if IS_WINDOWS else "trivy"
    },
    "gitleaks": {
        "url_win": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
        "url_linux": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "binary": "gitleaks.exe" if IS_WINDOWS else "gitleaks"
    },
    "ffuf": {
        "url_win": "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_windows_amd64.zip",
        "url_linux": "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz",
        "binary": "ffuf.exe" if IS_WINDOWS else "ffuf"
    }
}

def install_tools():
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    print("==================================================")
    print("  INSTALLATION DES OUTILS DE SÉCURITÉ EXTERNES")
    print("==================================================")

    for name, info in TOOL_RELEASES.items():
        dest_folder = TOOLS_DIR / name
        dest_folder.mkdir(parents=True, exist_ok=True)
        target_bin = dest_folder / info["binary"]

        if target_bin.exists():
            print(f"[DÉJÀ INSTALLÉ] {name} -> {target_bin}")
            continue

        url = info["url_win"] if IS_WINDOWS else info["url_linux"]
        archive_name = url.split("/")[-1]
        archive_path = dest_folder / archive_name

        print(f"[TÉLÉCHARGEMENT] {name} depuis {url}...")
        try:
            urllib.request.urlretrieve(url, archive_path)
            if archive_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(dest_folder)
            elif archive_name.endswith((".tar.gz", ".tgz")):
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(dest_folder)
            archive_path.unlink()
            print(f"[SUCCÈS] {name} installé avec succès.")
        except Exception as e:
            print(f"[ERREUR] Échec installation {name}: {e}")

    # Copy local if available in source project
    source_tools = Path(__file__).resolve().parent.parent / "site-cloner" / "security" / "sentinel" / "tools_bin"
    if source_tools.exists():
        for name in TOOL_RELEASES:
            src_bin = source_tools / name / (TOOL_RELEASES[name]["binary"])
            dst_bin = TOOLS_DIR / name / (TOOL_RELEASES[name]["binary"])
            if src_bin.exists() and not dst_bin.exists():
                shutil.copy2(src_bin, dst_bin)
                print(f"[COPIÉ LOCAL] {name} importé depuis le cache local.")

if __name__ == "__main__":
    install_tools()

# Adaptive Honeypot

Tento projekt implementuje **adaptívny honeypot** nad T-Pot platformou.  
Aktuálne podporuje dynamickú zmenu profilov pre:

- **Cowrie** (SSH/Telnet)
- **Dionaea** (SMB/FTP, prípadne ďalšie služby podľa profilov)

Základná myšlienka je jednoduchá:

1. honeypot beží na senzore v Docker kontajneroch,
2. jeho konfigurácia je uložená na hoste,
3. administrátor vie jedným skriptom prepnúť profil,
4. po prepnutí sa zmení identita honeypotu.

---

## Cieľ

Cieľom projektu je umožniť, aby sa honeypot vedel tváriť ako rôzne typy zariadení alebo systémov, napríklad:

- produkčný Linux server,
- vývojárska workstation,
- starý legacy systém,
- Windows SMB host,
- Samba fileserver,
- FTP server s iným bannerom.

Takáto zmena sa vykonáva **bez rebuildovania image** a bez manuálnych zásahov priamo do kontajnera.

---

## Architektúra

Honeypoty bežia v T-Pot prostredí cez Docker Compose.

Konfigurácia sa nemení priamo v kontajneri, ale cez **bind mounty** z hosta.  
To znamená, že host-side súbory sú namountované do kontajnera a po ich zmene stačí reštartovať príslušnú službu.

---

## Štruktúra projektu

```text
/home/filip/
├── adaptive_honeypot/
│   ├── apply_profile.sh
│   └── profiles/
│       ├── cowrie/
│       │   ├── default/
│       │   │   ├── cowrie.cfg
│       │   │   ├── userdb.txt
│       │   │   └── honeyfs/
│       │   ├── server/
│       │   │   ├── cowrie.cfg
│       │   │   ├── userdb.txt
│       │   │   └── honeyfs/
│       │   ├── workstation/
│       │   │   ├── cowrie.cfg
│       │   │   ├── userdb.txt
│       │   │   └── honeyfs/
│       │   └── legacy/
│       │       ├── cowrie.cfg
│       │       ├── userdb.txt
│       │       └── honeyfs/
│       └── dionaea/
│           ├── windows7/
│           │   ├── smb.yaml
│           │   └── ftp.yaml
│           ├── samba_linux/
│           │   ├── smb.yaml
│           │   └── ftp.yaml
│           └── legacy_xp/
│               ├── smb.yaml
│               └── ftp.yaml
│
└── tpotce/
    └── data/
        ├── cowrie/
        │   ├── config/
        │   │   └── cowrie.cfg
        │   ├── honeyfs/
        │   ├── keys/
        │   │   └── userdb.txt
        │   ├── downloads/
        │   └── log/
        └── dionaea/
            ├── services/
            │   ├── smb.yaml
            │   ├── ftp.yaml
            │   └── http.yaml
            ├── roots/
            ├── binaries/
            ├── log/
            └── rtp/
```

## Použitie skriptu `apply_profile.sh`

Skript slúži na prepnutie aktívneho profilu pre konkrétny honeypot bez manuálnej úpravy konfigurácie v T-Pot adresároch.

Syntax:

```bash
./apply_profile.sh <service> <profile|random>
```

Podporované služby:

- `cowrie`
- `dionaea`

Ak namiesto názvu profilu použiješ `random`, skript náhodne vyberie jeden z dostupných profilov pre danú službu.

Príklady:

```bash
./apply_profile.sh cowrie default
./apply_profile.sh cowrie server
./apply_profile.sh cowrie random

./apply_profile.sh dionaea windows7
./apply_profile.sh dionaea samba_linux
./apply_profile.sh dionaea random
```

Čo skript robí:

- pre `cowrie` skopíruje `cowrie.cfg`, `userdb.txt` a obsah `honeyfs/`,
- pre `dionaea` skopíruje `smb.yaml` a `ftp.yaml`, prípadne aj `http.yaml`, ak je v profile dostupný,
- následne reštartuje príslušný Docker Compose kontajner v T-Pot prostredí.

Poznámky:

- skript očakáva projekt v ceste `/home/filip/adaptive_honeypot`,
- T-Pot dáta očakáva v `/home/filip/tpotce`,
- na úspešné vykonanie potrebuje prístup k týmto adresárom a funkčný `docker compose`.

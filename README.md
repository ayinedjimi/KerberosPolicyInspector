# 🚀 Kerberos Policy Inspector


**Version:** 1.0
**Auteur:** Ayi NEDJIMI Consultants
**Date:** 2025

## 📋 Description

Inspecteur de politiques Kerberos permettant d'auditer les configurations de sécurité Kerberos du domaine Active Directory : durées de tickets, types de chiffrement supportés, détection des algorithmes faibles (DES, RC4), et recommandations de durcissement.


## ✨ Fonctionnalités

### 1. Interrogation Politiques Domaine
- Détection automatique du domaine AD
- Lecture des politiques Kerberos effectives (GPO appliquées localement)
- Extraction des paramètres critiques:
  - **MaxTicketAge** : Durée de vie du TGT
  - **MaxRenewAge** : Durée maximale de renouvellement
  - **MaxServiceAge** : Durée de vie des tickets de service
  - **MaxClockSkew** : Écart d'horloge autorisé

### 2. Analyse Encryption Types
- Détection des types de chiffrement supportés:
  - DES-CBC-CRC (obsolète - ALERTE)
  - DES-CBC-MD5 (obsolète - ALERTE)
  - RC4-HMAC (faible - Avertissement)
  - AES128-CTS-HMAC-SHA1-96 (recommandé)
  - AES256-CTS-HMAC-SHA1-96 (recommandé)
- Alertes si DES ou RC4 uniquement activés

### 3. Event Log - Erreurs Kerberos
- Requête Event Log pour erreurs Kerberos récentes
- Détection de downgrades d'encryption
- Identification des échecs d'authentification

### 4. Recommandations Sécurité
- Guide complet de hardening Kerberos
- Bonnes pratiques NIST 800-53, CIS Benchmarks
- Commandes pour migration vers AES256
- Configuration audit Kerberos

### 5. Export CSV
- Format UTF-8 avec BOM
- Colonnes: Politique, Valeur Actuelle, Recommandée, Sécurité, Notes


## Compilation

### Prérequis
- Visual Studio 2019/2022 avec MSVC
- Windows SDK 10.0 ou supérieur
- Machine jointe à un domaine Active Directory (recommandé)

### Build
```batch
go.bat
```

Ou manuellement:
```batch
cl.exe /O2 /EHsc /D_UNICODE /DUNICODE /D_WIN32_DCOM KerberosPolicyInspector.cpp ^
  /link comctl32.lib activeds.lib adsiid.lib netapi32.lib wevtapi.lib advapi32.lib ^
  ole32.lib oleaut32.lib user32.lib gdi32.lib shell32.lib
```


## 🚀 Utilisation

### Lancement
```batch
KerberosPolicyInspector.exe
```

**Note:** Fonctionne sur machines Standalone (valeurs par défaut) et jointes au domaine (politiques effectives).

### Interface

#### Boutons
- **Interroger Domaine** : Analyse complète des politiques Kerberos locales et domaine
- **Exporter Rapport** : Sauvegarde des résultats dans un fichier CSV
- **Afficher Recommandations** : Affiche le guide complet de sécurisation Kerberos

#### Colonnes ListView
- **Politique** : Nom du paramètre Kerberos (ex: MaxTicketAge)
- **Valeur Actuelle** : Valeur configurée sur le système
- **Recommandée** : Valeur recommandée selon les bonnes pratiques
- **Sécurité** : Niveau de sécurité (OK, Avertissement, CRITIQUE, Info)
- **Notes** : Description et alertes


## Architecture Technique

### APIs Utilisées
- **netapi32.lib** :
  - `NetGetJoinInformation()` - Détection du domaine AD
- **advapi32.lib** :
  - `RegOpenKeyExW()` - Lecture du registre
  - `RegQueryValueExW()` - Récupération des valeurs Kerberos
- **wevtapi.lib** :
  - `EvtQuery()` - Requête Event Log pour erreurs Kerberos
- **activeds.lib** : (Prêt pour future extension LDAP query)

### Registre Analysé
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`

### Event Log
- Canal: **System**
- Provider: **Microsoft-Windows-Security-Kerberos**
- Levels: Error (2) et Warning (3)


# 🚀 Via GPO: Computer Config > Policies > Windows Settings > Security Settings >

# 🚀 Local Policies > Security Options > Network security: Configure encryption types

# 🚀 Décocher: DES_CBC_CRC, DES_CBC_MD5

# 🚀 Via registre (si GPO impossible):

# 🚀 0x18 = 0x08 (AES128) + 0x10 (AES256)

# 🚀 Via GPO:

# 🚀 Ajouter comptes sensibles au groupe Protected Users:

# 🚀 - Force AES256

# 🚀 - Désactive RC4, DES, NTLM

# 🚀 - Limite durée de vie TGT à 4 heures (non-renouvelable)

## Logging

Les logs sont stockés dans:
```
%TEMP%\WinTools_KerberosPolicyInspector_log.txt
```

Format: Timestamp + message texte avec valeurs détectées


## 🚀 Cas d'Usage

### 1. Audit de Conformité
Vérifier que les politiques Kerberos respectent les standards NIST/CIS.

### 2. Migration vers AES
Valider que DES et RC4 sont désactivés avant la fin de vie RC4 (2025).

### 3. Troubleshooting Authentification
Identifier les mauvaises configurations (clock skew excessif, tickets expirés trop vite).

### 4. Hardening Domaine AD
Appliquer les recommandations pour renforcer la sécurité Kerberos.


## Interprétation des Résultats

### Niveaux de Sécurité

#### OK
Configuration conforme aux bonnes pratiques. Exemples:
- AES256 activé
- MaxTicketAge <= 10 heures
- MaxClockSkew <= 5 minutes

#### Avertissement
Configuration acceptable mais améliorable. Exemples:
- RC4 seul (sans DES mais sans AES)
- MaxTicketAge > 10 heures
- Erreurs Kerberos récentes dans Event Log

#### CRITIQUE
Configuration dangereuse nécessitant action immédiate. Exemples:
- DES activé (cassable en quelques heures)
- Pas d'encryption types modernes configurés

#### Info
Information contextuelle sans impact sécurité direct.

### Encryption Types - Détails

#### DES-CBC-CRC / DES-CBC-MD5
- **Statut:** Obsolète, désactivé par défaut depuis Windows 7
- **Risque:** Cassable en quelques heures avec GPU moderne
- **Action:** Désactiver immédiatement

#### RC4-HMAC
- **Statut:** Faible, déprécié
- **Risque:** Vulnérable à certaines attaques (Golden Ticket, etc.)
- **Action:** Migrer vers AES256 avant fin 2025

#### AES128-CTS-HMAC-SHA1-96
- **Statut:** Acceptable
- **Risque:** Minimal
- **Action:** Préférer AES256 si possible

#### AES256-CTS-HMAC-SHA1-96
- **Statut:** Recommandé
- **Risque:** Aucun (état de l'art 2025)
- **Action:** Déployer sur tous les systèmes

### Valeurs Recommandées

| Politique      | Défaut Windows | Recommandé  | Raison                           |
|----------------|----------------|-------------|----------------------------------|
| MaxTicketAge   | 10 heures      | 10 heures   | Équilibre sécurité/usabilité     |
| MaxRenewAge    | 7 jours        | 7 jours     | Limite la durée de compromission |
| MaxServiceAge  | 600 minutes    | 600 minutes | Suffisant pour la plupart des cas|
| MaxClockSkew   | 5 minutes      | 5 minutes   | Évite replay attacks             |
| MaxTokenSize   | 48000 octets   | 48000       | Support Kerberos + SID History   |


## Recommandations Détaillées

### 1. Désactiver DES
```powershell

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" ^
  /v SupportedEncryptionTypes /t REG_DWORD /d 0x18 /f
```

### 2. Activer Audit Kerberos
```powershell
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

### 3. Protected Users Group
```powershell

Add-ADGroupMember -Identity "Protected Users" -Members "AdminAccount"
```

### 4. Monitoring Event IDs
| Event ID | Description                      | Action                          |
|----------|----------------------------------|---------------------------------|
| 4768     | TGT Request (KDC)                | Baseline normal, alerter pics   |
| 4769     | Service Ticket Request           | Surveiller services anormaux    |
| 4771     | Pre-auth failed                  | Alerte brute-force/spray        |
| 4772     | Kerberos ticket request failed   | Investiguer échecs répétés      |


## Limitations

- **Politiques effectives locales** : L'outil lit les politiques appliquées localement via GPO, pas directement depuis l'AD (requiert LDAP complexe)
- **Machine Standalone** : Sur workgroup, seules les valeurs par défaut Windows sont affichées
- **Pas de modification** : Lecture seule - ne modifie aucune politique
- **Event Log limité** : Seules les erreurs récentes sont détectées


## Exemple Output

```
Politique                | Valeur Actuelle          | Recommandée      | Sécurité      | Notes
- ------------------------|--------------------------|------------------|---------------|---------------------------
Domaine Detecte          | DC=CORP,DC=LOCAL         |                  | Info          | Machine jointe au domaine
MaxTicketAge             | 10 heures                | 10 heures        | OK            | Durée de vie TGT
MaxRenewAge              | 7 jours                  | 7 jours          | OK            | Durée renouvellement
MaxServiceAge            | 600 minutes              | 600 minutes      | OK            | Durée ticket service
MaxClockSkew             | 5 minutes                | 5 minutes        | OK            | Écart d'horloge
SupportedEncryptionTypes | RC4-HMAC AES128 AES256   | AES256 AES128    | Avertissement | RC4 présent - migrer AES
MaxTokenSize             | 48000                    | 48000            | OK            | Taille max token
Event Log Kerberos       | 3 erreur(s) recente(s)   | 0 erreurs        | Avertissement | Vérifier downgrades
```


## 🔧 Dépannage

### Domaine non détecté
- Vérifier que la machine est jointe au domaine (`nltest /query`)
- Valeurs par défaut Windows seront affichées si workgroup

### Pas de politiques Kerberos trouvées
- Les politiques sont appliquées via GPO - vérifier `gpresult /r`
- Sur standalone, les clés registre peuvent ne pas exister (valeurs hardcodées dans lsass.exe)

### Event Log vide
- Vérifier que l'audit Kerberos est activé (`auditpol /get /category:*`)
- Pas d'erreurs = bon signe (mais vérifier que les events sont bien générés)


## Conformité et Standards

### NIST 800-53
- **IA-5(1)** : Password-based Authentication - Strong cryptography
- **SC-13** : Cryptographic Protection - FIPS 140-2 approved algorithms

### CIS Benchmarks
- **2.3.11.1** : Ensure 'Network security: Configure encryption types allowed for Kerberos' includes AES256
- **2.3.11.2** : Ensure 'Network security: Do not store LAN Manager hash' is Enabled

### PCI-DSS
- **Requirement 8.2.3** : Strong cryptography to render authentication credentials unreadable


## 📄 Licence

(c) 2025 Ayi NEDJIMI Consultants - Tous droits réservés


## Support

Pour questions ou support: contact@ayinedjimi-consultants.com


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>
# 🔐 BitLocker Network Unlock Deployment

> 🚀 Automated PowerShell deployment for BitLocker Network Unlock with WDS, certificate provisioning, subnet policy, and GPO configuration.

---

## 📑 Table of Contents

* [✨ Features](#-features)
* [📦 Repository Structure](#-repository-structure)
* [⚙️ Requirements](#️-requirements)
* [🚀 Usage](#-usage)
* [🔧 Parameters](#-parameters)
* [🧠 How It Works](#-how-it-works)
* [🔒 Security Considerations](#-security-considerations)
* [📁 Output & Artifacts](#-output--artifacts)
* [🧪 Validation](#-validation)
* [⚠️ Important Notes](#️-important-notes)
* [📈 Improvements](#-improvements)
* [👤 Author](#-author)
* [📄 License](#-license)

---

## ✨ Features

✅ Fully automated BitLocker Network Unlock deployment
✅ WDS installation & initialization
✅ Certificate generation:

* Self-signed (default)
* AD CS integration (optional)

✅ Automatic import into Network Unlock store (`FVENKP`)
✅ Optional subnet restriction (`bde-network-unlock.ini`)
✅ GPO creation & configuration:

* TPM + PIN enforcement
* Recovery key backup to AD DS
* Network Unlock enablement

✅ Secure handling of sensitive files (.pfx cleanup option)
✅ Logging with PowerShell transcript
✅ Safe execution with `-Force` protections

---

## 📦 Repository Structure

```
.
├── .gitattributes
├── Deploy-UFCV-BitLockerNetworkUnlock.ps1
└── README.md
```

---

## ⚙️ Requirements

### 🖥️ Server

* Windows Server (2016+ recommended)
* PowerShell (Admin mode)
* Domain-joined machine

### 📡 Features / Roles

* WDS (Windows Deployment Services)
* BitLocker Network Unlock
* RSAT AD PowerShell
* GPMC

### 🔐 Permissions

* Local Administrator
* Domain Admin (for GPO mode)

---

## 🚀 Usage

### 🔹 Full deployment

```powershell
.\Deploy-UFCV-BitLockerNetworkUnlock.ps1 -Mode All -Force
```

---

### 🔹 Server only (WDS + certificate)

```powershell
.\Deploy-UFCV-BitLockerNetworkUnlock.ps1 -Mode ServerOnly
```

---

### 🔹 GPO only

```powershell
.\Deploy-UFCV-BitLockerNetworkUnlock.ps1 -Mode GpoOnly -Force
```

---

### 🔹 With subnet restriction

```powershell
.\Deploy-UFCV-BitLockerNetworkUnlock.ps1 `
    -Mode All `
    -AllowedSubnets "10.11.0.0/16","192.168.1.0/24" `
    -Force
```

---

### 🔹 With AD CS certificate

```powershell
.\Deploy-UFCV-BitLockerNetworkUnlock.ps1 `
    -Mode All `
    -UseAdcs `
    -CaConfig "CA01\UFCV-CA" `
    -TemplateName "BitLocker Network Unlock" `
    -Force
```

---

## 🔧 Parameters

| Parameter                | Description                      |
| ------------------------ | -------------------------------- |
| `-Mode`                  | `All`, `ServerOnly`, `GpoOnly`   |
| `-GpoName`               | Name of the GPO                  |
| `-WorkstationsLinkDN`    | Target OU DN                     |
| `-MinPin`                | Minimum TPM PIN                  |
| `-AllowedSubnets`        | Restrict Network Unlock subnets  |
| `-EnableWdsDebugLog`     | Enable debug logging             |
| `-RotateCertificate`     | Force certificate renewal        |
| `-CleanupSensitiveFiles` | Delete PFX after import          |
| `-UseAdcs`               | Use AD CS instead of self-signed |
| `-CaConfig`              | CA server config                 |
| `-TemplateName`          | Certificate template             |
| `-Force`                 | Allow sensitive operations       |

---

## 🧠 How It Works

### 1️⃣ Install required roles

* WDS Deployment
* WDS Transport
* BitLocker Network Unlock

---

### 2️⃣ Initialize WDS

* Checks existing configuration
* Initializes if needed (with `-Force`)

---

### 3️⃣ Certificate provisioning

* Generates or requests certificate
* Adds BitLocker Network Unlock OID
* Exports `.cer` and `.pfx`

---

### 4️⃣ Import into Network Unlock store

```bash
certutil -importpfx FVENKP
```

---

### 5️⃣ Subnet policy (optional)

* Generates `bde-network-unlock.ini`
* Restricts allowed networks

---

### 6️⃣ GPO configuration

Registry path:

```
HKLM\SOFTWARE\Policies\Microsoft\FVE
```

Includes:

* TPM + PIN enforcement
* AD backup
* Network Unlock flag

---

## 🔒 Security Considerations

⚠️ The `.pfx` file contains a private key
👉 Use `-CleanupSensitiveFiles` in production

⚠️ GPO linking at domain level can be risky
👉 Prefer targeting a specific OU

⚠️ Network Unlock reduces pre-boot authentication
👉 Use only on trusted networks

---

## 📁 Output & Artifacts

Generated in:

```
C:\UFCV\BitLockerNetworkUnlock
```

Includes:

* `.cer` (public certificate)
* `.pfx` (private key)
* `.log` (deployment logs)
* `.inf/.req` (AD CS mode)

---

## 🧪 Validation

### ✔️ Check protector

```powershell
manage-bde -protectors -get C:
```

Look for:

```
Network Unlock
```

---

### ✔️ Check certificate (client)

```
HKLM\Software\Policies\Microsoft\SystemCertificates\FVE_NKP
```

---

### ✔️ Apply GPO

```powershell
gpupdate /force
```

---

## ⚠️ Important Notes

❗ The script **cannot fully automate GPO certificate injection**

👉 Manual step required:

```
GPMC → GPO → Public Key Policies → 
BitLocker Network Unlock Certificate → Add certificate
```

---

## 📈 Improvements

* 🔄 Full automation of certificate injection in GPO
* 📊 Monitoring / logging enhancements
* 🌐 GUI wrapper (optional)
* 🧪 Lab validation scripts

---

## 👤 Author

**UFCV DSI – Infrastructure & Systems**

---

## 📄 License

MIT License (recommended for reuse)

<# 
Deploy-UFCV-BitLockerNetworkUnlock.ps1
- Installe/valide WDS + BitLocker-NetworkUnlock
- Génère un certificat Network Unlock (self-signed) conforme à l’OID BitLocker Network Unlock
- Importe la clé privée dans le store Network Unlock (FVENKP via certutil)
- (Optionnel) Crée bde-network-unlock.ini pour restreindre les subnets
- (Optionnel) Crée/MAJ un GPO BitLocker (TPM+PIN, backup AD, Network Unlock flag)
- Produit un dossier d’artefacts (CER/PFX/logs) pour redéploiement

⚠️ À lancer en PowerShell admin sur Windows Server, avec droits Domain Admin si Mode inclut GpoOnly/All.
#>

[CmdletBinding()]
param(
    [ValidateSet("All","ServerOnly","GpoOnly")]
    [string]$Mode = "All",

    # ---- GPO ----
    [string]$GpoName = "UFCV - BitLocker (TPM+PIN) + Network Unlock",
    [string]$WorkstationsLinkDN = "",   # DN (OU recommandé). Si vide -> lien au niveau du domaine (⚠️ large)
    [int]$MinPin = 6,

    # ---- WDS / Network Unlock ----
    [string]$RemoteInstallPath = "C:\RemoteInstall",
    [string[]]$AllowedSubnets = @(),     # ex: "10.11.0.0/16"
    [switch]$EnableWdsDebugLog,

    # ---- Cert ----
    [string]$CertSubject = "CN=BitLocker Network Unlock certificate",
    [switch]$RotateCertificate,          # force une rotation de cert même si une existe
    [switch]$CleanupSensitiveFiles,      # supprime PFX après import
    [string]$OutputDir = "C:\UFCV\BitLockerNetworkUnlock",

    # ---- Safety ----
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------
# Pretty output helpers
# ----------------------------
function Write-Title($t) { Write-Host ""; Write-Host ("="*80) -ForegroundColor DarkCyan; Write-Host ("🧩 " + $t) -ForegroundColor Cyan; Write-Host ("="*80) -ForegroundColor DarkCyan }
function Write-Step($t)  { Write-Host (" ➜ " + $t) -ForegroundColor Gray }
function Write-OK($t)    { Write-Host (" ✅ " + $t) -ForegroundColor Green }
function Write-Warn($t)  { Write-Host (" ⚠️  " + $t) -ForegroundColor Yellow }
function Write-Bad($t)   { Write-Host (" ❌ " + $t) -ForegroundColor Red }
function Write-Info($t)  { Write-Host (" ℹ️  " + $t) -ForegroundColor DarkGray }

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Ce script doit être exécuté en administrateur (Run as Administrator)." }
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
}

function Try-ImportModule([string]$Name) {
    try { Import-Module $Name -ErrorAction Stop; return $true } catch { return $false }
}

function Ensure-WindowsFeature([string]$FeatureName) {
    $f = Get-WindowsFeature -Name $FeatureName -ErrorAction Stop
    if ($f.Installed) {
        Write-OK "Feature déjà installée : $FeatureName"
        return
    }
    Write-Step "Installation feature : $FeatureName"
    Install-WindowsFeature -Name $FeatureName -IncludeManagementTools | Out-Null
    Write-OK "Installé : $FeatureName"
}

function Get-DomainInfoOrNull {
    try {
        if (-not (Try-ImportModule "ActiveDirectory")) { return $null }
        return Get-ADDomain -ErrorAction Stop
    } catch { return $null }
}

function Get-Fqdn {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $dn = $cs.Domain
        $hn = $env:COMPUTERNAME
        if ([string]::IsNullOrWhiteSpace($dn) -or $dn -eq $hn) { return $hn }
        return "$hn.$dn"
    } catch {
        return $env:COMPUTERNAME
    }
}

function New-RandomPassword([int]$Len = 32) {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*_-+=".ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] ($Len)
    $rng.GetBytes($bytes)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($chars[$b % $chars.Length]) }
    return $sb.ToString()
}

function Find-ExistingNetworkUnlockCert {
    # On cherche d’abord dans LocalMachine\My via Subject, car on génère là.
    $all = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
    if (-not $all) { return $null }
    $match = $all | Where-Object { $_.Subject -eq $CertSubject } | Sort-Object NotAfter -Descending | Select-Object -First 1
    return $match
}

function Create-SelfSignedNetworkUnlockCert([string]$Fqdn) {
    # Conforme à l’exemple Microsoft (OID Network Unlock dans extensions)
    Write-Step "Création certificat self-signed Network Unlock (LocalMachine\\My)"
    $cert = New-SelfSignedCertificate `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -Subject $CertSubject `
        -DnsName $Fqdn `
        -Provider "Microsoft Software Key Storage Provider" `
        -KeyUsage KeyEncipherment `
        -KeyUsageProperty Decrypt,Sign `
        -KeyLength 2048 `
        -HashAlgorithm sha512 `
        -TextExtension @(
            "1.3.6.1.4.1.311.21.10={text}OID=1.3.6.1.4.1.311.67.1.1",
            "2.5.29.37={text}1.3.6.1.4.1.311.67.1.1"
        )
    Write-OK ("Cert créé : Thumbprint=" + $cert.Thumbprint)
    return $cert
}

function Export-NetworkUnlockCert([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$OutDir) {
    Ensure-Dir $OutDir
    $cerPath = Join-Path $OutDir "BitLocker-NetworkUnlock.cer"
    $pfxPath = Join-Path $OutDir "BitLocker-NetworkUnlock.pfx"

    Write-Step "Export public key (.cer) -> $cerPath"
    Export-Certificate -Cert $Cert -FilePath $cerPath | Out-Null
    Write-OK "Export .cer OK"

    $plain = New-RandomPassword 32
    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force

    Write-Step "Export avec clé privée (.pfx) -> $pfxPath"
    Export-PfxCertificate -Cert $Cert -FilePath $pfxPath -Password $secure | Out-Null
    Write-OK "Export .pfx OK"

    return [pscustomobject]@{
        CerPath = $cerPath
        PfxPath = $pfxPath
        PfxPasswordPlain = $plain
    }
}

function Import-PfxToFVENKP([string]$PfxPath, [string]$PfxPasswordPlain) {
    # Import dans le store Network Unlock (FVENKP) via certutil
    Write-Step "Import PFX dans le store Network Unlock (FVENKP) via certutil"
    $args = @("-f","-p",$PfxPasswordPlain,"-importpfx","FVENKP",$PfxPath)
    $p = Start-Process -FilePath "certutil.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -ne 0) { throw "certutil importpfx a échoué (ExitCode=$($p.ExitCode))." }
    Write-OK "Import dans FVENKP OK"
}

function Restart-WdsIfPresent {
    $svc = Get-Service -Name "WDSServer" -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Warn "Service WDSServer introuvable (WDS pas installé ?)."; return }
    Write-Step "Redémarrage WDSServer"
    Restart-Service -Name "WDSServer" -Force
    Write-OK "WDSServer redémarré"
}

function Ensure-WdsInitialized {
    # Network Unlock n’exige pas une conf WDS “PXE complete”, mais dans la vraie vie, WDS peut rester non initialisé.
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WDSServer\Parameters"
    $root = $null
    try { $root = (Get-ItemProperty -Path $regPath -Name "RootFolder" -ErrorAction Stop).RootFolder } catch {}
    if ($root) {
        Write-OK "WDS semble déjà initialisé (RootFolder=$root)"
        return
    }

    Write-Warn "WDS semble non initialisé. Initialisation WDS (wdsutil /Initialize-Server)."
    if (-not $Force) {
        throw "Refus d'initialiser WDS sans -Force (sécurité). Relance avec -Force si c’est voulu."
    }

    Ensure-Dir $RemoteInstallPath
    $args = @("/Initialize-Server","/RemInst:$RemoteInstallPath","/Answer:Yes")
    $p = Start-Process -FilePath "wdsutil.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -ne 0) { throw "wdsutil /Initialize-Server a échoué (ExitCode=$($p.ExitCode))." }
    Write-OK "WDS initialisé"
}

function Write-SubnetPolicyIni([string]$ThumbprintNoSpaces, [string[]]$Subnets) {
    if (-not $Subnets -or $Subnets.Count -eq 0) {
        Write-Info "AllowedSubnets vide -> pas de bde-network-unlock.ini (comportement par défaut : pas de restriction)"
        return
    }

    $iniPath = Join-Path $env:windir "System32\bde-network-unlock.ini"   # même dossier que Nkpprov.dll
    $backup = $iniPath + ".bak_" + (Get-Date -Format "yyyyMMdd_HHmmss")

    if (Test-Path $iniPath) {
        Copy-Item $iniPath $backup -Force
        Write-Warn "bde-network-unlock.ini existant sauvegardé -> $backup"
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("[SUBNETS]")
    for ($i=0; $i -lt $Subnets.Count; $i++) {
        $name = "SUBNET$($i+1)"
        $lines.Add("$name=$($Subnets[$i])")
    }
    $lines.Add("")
    $lines.Add("[$ThumbprintNoSpaces]")
    for ($i=0; $i -lt $Subnets.Count; $i++) {
        $lines.Add("SUBNET$($i+1)")
    }
    $lines.Add("")

    Write-Step "Écriture subnet policy -> $iniPath"
    $lines | Out-File -FilePath $iniPath -Encoding ASCII -Force
    Write-OK "Subnet policy écrite (restrictions actives pour ce thumbprint)"
}

function Ensure-WdsDebugLog {
    if (-not $EnableWdsDebugLog) { return }
    # WDS debug log se gère classiquement via wdsutil /Set-Server /Transport /EnableTftpVariableWindowExtension etc,
    # mais ici on se contente d’activer le logging DHCP provider si dispo (varie selon versions).
    Write-Warn "Option DebugLog demandée. Selon version serveur, l’emplacement/paramètre exact peut varier."
    Write-Info "Astuce : utilise les logs WDS + manage-bde côté client pour vérifier le thumbprint."
}

function Ensure-GpoBitLocker([Microsoft.GroupPolicy.Gpo]$gpo, [int]$MinPin) {
    # Policies via registry values dans HKLM\SOFTWARE\Policies\Microsoft\FVE
    $k = "HKLM\SOFTWARE\Policies\Microsoft\FVE"

    Write-Step "Configuration registry policies BitLocker dans le GPO (FVE)"

    # --- Network Unlock flag ---
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "OSManageNKP" -Type DWord -Value 1

    # --- Require additional auth at startup: TPM + PIN (enforcement “classique”) ---
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "UseAdvancedStartup" -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "UseTPM"          -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "UseTPMPIN"       -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "UseTPMKey"       -Type DWord -Value 0
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "UseTPMKeyPIN"    -Type DWord -Value 0
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "UsePIN"          -Type DWord -Value 0

    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "MinimumPIN"      -Type DWord -Value $MinPin
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "UseEnhancedPin"  -Type DWord -Value 1

    # --- Backup recovery info to AD DS (OS + Fixed + Removable) ---
    # OS drives
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "OSActiveDirectoryBackup"        -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "OSRequireActiveDirectoryBackup" -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "OSActiveDirectoryInfoToStore"   -Type DWord -Value 1

    # Fixed data drives
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "FDVActiveDirectoryBackup"        -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "FDVRequireActiveDirectoryBackup" -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "FDVActiveDirectoryInfoToStore"   -Type DWord -Value 1

    # Removable data drives
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "RDVActiveDirectoryBackup"        -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "RDVRequireActiveDirectoryBackup" -Type DWord -Value 1
    Set-GPRegistryValue -Name $gpo.DisplayName -Key $k -ValueName "RDVActiveDirectoryInfoToStore"   -Type DWord -Value 1

    Write-OK "GPO registry policies configurées"
}

# ----------------------------
# Main
# ----------------------------
Write-Title "Déploiement BitLocker + Network Unlock (UFCV) — Mode: $Mode"

Assert-Admin
Ensure-Dir $OutputDir

$logPath = Join-Path $OutputDir ("deploy_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
Start-Transcript -Path $logPath -Append | Out-Null
Write-Info "Log : $logPath"

try {
    # --- Basic sanity checks ---
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Info ("OS : " + $os.Caption + " (" + $os.Version + ")")

    if ($Mode -in @("All","ServerOnly")) {
        Write-Title "1) Installation / validation des rôles & features (WDS + BitLocker-NetworkUnlock)"

        if (-not (Try-ImportModule "ServerManager")) {
            throw "Module ServerManager introuvable. Ce script est prévu pour Windows Server (Get/Install-WindowsFeature)."
        }

        # D’après Microsoft: WDS + BitLocker-NetworkUnlock :contentReference[oaicite:4]{index=4}
        Ensure-WindowsFeature "WDS-Deployment"
        Ensure-WindowsFeature "WDS-Transport"
        Ensure-WindowsFeature "BitLocker-NetworkUnlock"

        # Outils d’admin pratiques
        Ensure-WindowsFeature "RSAT-AD-PowerShell"
        Ensure-WindowsFeature "GPMC"

        $svc = Get-Service -Name "WDSServer" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Write-Step "Démarrage WDSServer"
            Start-Service "WDSServer"
            Write-OK "WDSServer démarré"
        } elseif ($svc) {
            Write-OK "WDSServer déjà en cours d’exécution"
        }

        Ensure-WdsInitialized
        Ensure-WdsDebugLog

        Write-Title "2) Certificat Network Unlock (création/rotation + import serveur)"

        $fqdn = Get-Fqdn
        Write-Info "FQDN serveur : $fqdn"

        $existing = Find-ExistingNetworkUnlockCert
        if ($existing -and -not $RotateCertificate) {
            Write-Warn "Cert existant détecté (LocalMachine\\My) : $($existing.Thumbprint)"
            Write-Info "Rotation désactivée -> on réutilise ce cert. (Ajoute -RotateCertificate pour en créer un nouveau.)"
            $cert = $existing
        } else {
            if ($existing -and $RotateCertificate) {
                Write-Warn "Rotation activée : un nouveau cert va être créé (l’ancien reste dans My, tu peux le nettoyer ensuite)."
            }
            $cert = Create-SelfSignedNetworkUnlockCert -Fqdn $fqdn
        }

        $export = Export-NetworkUnlockCert -Cert $cert -OutDir $OutputDir

        Import-PfxToFVENKP -PfxPath $export.PfxPath -PfxPasswordPlain $export.PfxPasswordPlain
        Restart-WdsIfPresent

        # Optionnel: bde-network-unlock.ini pour subnets :contentReference[oaicite:5]{index=5}
        Write-Title "3) Subnet policy (optionnel)"
        $thumb = ($cert.Thumbprint -replace "\s","")
        Write-SubnetPolicyIni -ThumbprintNoSpaces $thumb -Subnets $AllowedSubnets
        Restart-WdsIfPresent

        if ($CleanupSensitiveFiles) {
            Write-Warn "Nettoyage demandé : suppression du .pfx"
            Remove-Item -Path $export.PfxPath -Force -ErrorAction SilentlyContinue
            Write-OK ".pfx supprimé"
        }

        Write-Title "4) Artefacts générés"
        Write-OK "Public cert (.cer) : $($export.CerPath)"
        if (-not $CleanupSensitiveFiles) {
            Write-Warn "PFX conservé (.pfx) : $($export.PfxPath)  (contient clé privée)"
        }
        Write-Info "À importer dans GPMC: Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > BitLocker Drive Encryption Network Unlock Certificate :contentReference[oaicite:6]{index=6}"
    }

    if ($Mode -in @("All","GpoOnly")) {
        Write-Title "5) GPO BitLocker (TPM+PIN + AD backup + Network Unlock flag)"

        if (-not (Try-ImportModule "GroupPolicy")) { throw "Module GroupPolicy (GPMC) introuvable." }
        if (-not (Try-ImportModule "ActiveDirectory")) { throw "Module ActiveDirectory introuvable." }

        $domain = Get-ADDomain
        Write-Info "Domaine : $($domain.DNSRoot)"
        Write-Info "DN domaine : $($domain.DistinguishedName)"

        if ([string]::IsNullOrWhiteSpace($WorkstationsLinkDN)) {
            $WorkstationsLinkDN = $domain.DistinguishedName
            Write-Warn "WorkstationsLinkDN non fourni -> lien GPO au niveau du domaine (⚠️ très large)."
        } else {
            Write-OK "Lien GPO cible : $WorkstationsLinkDN"
        }

        $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            Write-Step "Création GPO : $GpoName"
            $gpo = New-GPO -Name $GpoName
            Write-OK "GPO créé : $($gpo.Id)"
        } else {
            Write-OK "GPO existant : $($gpo.DisplayName) ($($gpo.Id))"
        }

        # Configure policies
        Ensure-GpoBitLocker -gpo $gpo -MinPin $MinPin

        # Link if not linked (best effort)
        $inherit = Get-GPInheritance -Target $WorkstationsLinkDN
        $alreadyLinked = $false
        foreach ($l in $inherit.GpoLinks) {
            if ($l.DisplayName -eq $GpoName -and $l.Enabled) { $alreadyLinked = $true }
        }

        if ($alreadyLinked) {
            Write-OK "GPO déjà lié et activé sur $WorkstationsLinkDN"
        } else {
            if (-not $Force) {
                throw "Le lien GPO va être créé. Relance avec -Force pour autoriser (sécurité)."
            }
            Write-Step "Création du lien GPO"
            New-GPLink -Name $GpoName -Target $WorkstationsLinkDN -LinkEnabled Yes | Out-Null
            Write-OK "Lien GPO créé"
        }

        Write-Title "6) IMPORTANT — Déploiement du .CER (étape GPMC)"
        Write-Warn "Le script ne peut pas injecter proprement à 100% la cert dans 'Public Key Policies' via un cmdlet natif."
        Write-Info "Fais-le en 30 secondes dans GPMC (Microsoft):"
        Write-Host "  1) Ouvre gpmc.msc" -ForegroundColor Gray
        Write-Host "  2) Édite le GPO: $GpoName" -ForegroundColor Gray
        Write-Host "  3) Va à: Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > BitLocker Drive Encryption Network Unlock Certificate" -ForegroundColor Gray
        Write-Host "  4) Right-click > Add Network Unlock Certificate > importe BitLocker-NetworkUnlock.cer" -ForegroundColor Gray
        Write-Info "Côté client, tu pourras voir la cert sous HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\FVE_NKP :contentReference[oaicite:7]{index=7}"
        Write-Info "Et valider la présence du protector Network Unlock via: manage-bde -protectors -get C: (protector '9') :contentReference[oaicite:8]{index=8}"
    }

    Write-Title "✅ Terminé"
    Write-OK "Déploiement terminé. Log complet: $logPath"
    Write-Info "Pense à: gpupdate /force + reboot des clients après déploiement GPO/cert (requis côté Network Unlock). :contentReference[oaicite:9]{index=9}"
}
catch {
    Write-Title "💥 Erreur"
    Write-Bad $_.Exception.Message
    Write-Info "Log: $logPath"
    throw
}
finally {
    Stop-Transcript | Out-Null
}
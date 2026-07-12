# Arc Decrypt

Arc Decrypt is a tool for enumerating Azure Arc deployments and decrypting the `encryptedServicePrincipalSecret` used during Azure Arc onboarding.

When Azure Arc is deployed via Group Policy Object (GPO), the service principal secret is encrypted, stored on a file share, and made accessible to machine accounts. This tool attempts to automatically locate the deployment share and uses DPAPI-NG (NCryptProtectSecret) to unwrap the secret.
- https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-group-policy-powershell

## Features

- **GPO Discovery**: Automatically scans LDAP and SYSVOL to discover Azure Arc deployment GPOs and network shares.
- **SMB Share Hunting**: Keyword-based fallback enumeration to find deployment shares across Domain Controllers.
- **Automated Decryption**: Handles DPAPI-NG decryption for the `encryptedServicePrincipalSecret`.
- **Machine Account Auto-Creation**: Dynamically provisions a temporary machine account (which is typically granted decryption rights via DPAPI-NG) using standard domain user credentials.
- **Kerberos Authentication**: Full Kerberos support via ccache (SMB, LDAP, SAMR, and DPAPI-NG).


## Authentication

The tool supports three authentication methods (mutually exclusive):

| Method | Flags | Notes |
|--------|-------|-------|
| Password | `-u USER -p PASS` | NTLM |
| NTLM hash | `-u USER -H LM:NT` | Overpass-the-hash; `LM:NT` or bare `NT` hex |
| Kerberos | `-u USER -k` or `-u USER -ccache /path/to/ccache` | Requires `gssapi` + `krb5` packages (see below) |

**Kerberos setup:**
```bash
# Install system + Python dependencies
apt install libkrb5-dev gcc python3-dev
pip install dpapi-ng[kerberos]

# Obtain a TGT (any method)
kinit administrator@CONTOSO.LOCAL
# or: impacket-getTGT contoso.local/administrator:Password123!
# or: impacket-getTGT -hashes :admlm contoso.local/administrator

# Use the tool with -k (reads KRB5CCNAME env var)
export KRB5CCNAME=/tmp/krb5cc_1000
python3 arc-decrypt.py find -d contoso.local -dc-ip 10.0.0.5 -dc dc01.contoso.local -u administrator -k

# Or specify a ccache path directly (implies -k)
python3 arc-decrypt.py find -d contoso.local -dc-ip 10.0.0.5 -dc dc01.contoso.local -u administrator -ccache /tmp/krb5cc_1000
```

> **Note:** When using Kerberos (`-k`) with an IP address for `-dc-ip`, you must also provide `-dc <hostname>` so the tool can derive the correct Kerberos SPN. If `-dc-ip` is a hostname, `-dc` is optional.


## Usage

The tool operates using two primary subcommands: `find` and `decrypt`.

**Install**

```bash
sudo apt install libkrb5-dev gcc python3-dev
pip3 install -r requirements.txt
```

### 1. Find Mode

Detects Arc GPOs and identifies the deployment share where secrets and onboarding scripts (`AzureArcDeployment.psm1`, `ArcInfo.json`) reside.

By default both discovery methods are used: GPO/SYSVOL parsing first, then SMB keyword enumeration as a fallback. Use `--gpo` or `--smb` to restrict to a single method.

**Arguments:**
- `-d DOMAIN`: Domain FQDN (e.g., `contoso.local`)
- `-dc-ip DC`: Domain Controller FQDN or IP
- `-u USERNAME`: Domain username
- `-p PASSWORD`: Domain user password (mutually exclusive with `-H` and `-k`)
- `-H LM:NT`: NTLM hash for authentication, as `LM:NT` or a bare `NT` hex string (mutually exclusive with `-p` and `-k`)
- `-k`, `-kerberos`: Use Kerberos authentication (requires valid ccache; see [Authentication](#authentication))
- `-ccache PATH`: Path to Kerberos ccache file (implies `-k`)
- `-v`, `-verbose`: Show every discovery step in detail
- `-debug-sysvol`: (Optional) Walk and print the full GPO SYSVOL directory tree
- `--gpo`: Only use GPO/SYSVOL detection
- `--smb`: Only use SMB keyword share enumeration (scans all Domain Controllers)

**Examples:**

*Password authentication, auto discovery (GPO then SMB):*
```bash
python3 arc-decrypt.py find -d contoso.local -dc-ip 10.0.0.5 -u "jsmith" -p "Password123!"
```

*NTLM hash authentication, GPO-only detection:*
```bash
python3 arc-decrypt.py find -d contoso.local -dc-ip 10.0.0.5 -u "jsmith" -H "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" --gpo -v
```

*Kerberos authentication:*
```bash
python3 arc-decrypt.py find -d contoso.local -dc-ip 10.0.0.5 -u "jsmith" -k
```

### 2. Decrypt Mode

Locates and decrypts the `encryptedServicePrincipalSecret`. You must authenticate as a machine account, either explicitly or by allowing the tool to create a temporary one.

**Auth Modes:**
- **Auto Mode (`-auto`)**: Supply standard user credentials (`-u` and `-p`), and the tool will automatically create a temporary machine account, perform the decryption, and provide the secret. (Note: Requires rights to add machine accounts, e.g., via `ms-DS-MachineAccountQuota`).
- **Explicit Machine Account**: Pass an existing machine account (`-u MACHINE$ -p PASS`).

Both auth modes accept either a password (`-p`), an NTLM hash (`-H LM:NT` or bare `-H NT`), or Kerberos (`-k` / `-ccache`).

**Optional Arguments:**
- `-share UNC`: Explicitly specify the UNC path of the share if auto-discovery fails.
- `-dump-blob PATH`: Save the decoded DPAPI-NG blob to a file for offline analysis.
- `-v`, `-verbose`: Show detailed blob internals and DpapiNgUtil source parsing.

**Examples:**

*Auto-create a machine account to decrypt the secret:*
```bash
python3 arc-decrypt.py decrypt -d contoso.local -dc-ip 10.0.0.5 -auto -u "jsmith" -p "Password123!"
```

*Use an existing machine account with an NTLM hash:*
```bash
python3 arc-decrypt.py decrypt -d contoso.local -dc-ip 10.0.0.5 -u "WS01$" -H "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
```

*Kerberos authentication with auto machine account creation:*
```bash
python3 arc-decrypt.py decrypt -d contoso.local -dc-ip 10.0.0.5 -auto -u "jsmith" -k
```

*Explicitly provide the share UNC path:*
```bash
python3 arc-decrypt.py decrypt -d contoso.local -dc-ip 10.0.0.5 -share "\\DC01.contoso.local\ArcShare" -auto -u "jsmith" -p "Password123!"
```

## Disclaimer

This tool is intended for educational and authorized security auditing purposes only. Always obtain explicit permission before testing network environments or extracting credentials.

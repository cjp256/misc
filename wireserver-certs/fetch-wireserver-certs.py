#!/usr/bin/env python3
# Minimal script to fetch all public SSH keys from Azure wireserver.
# Requirements: openssl, ssh-keygen present in PATH.

import os
import sys
import tempfile
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
import pprint

DEFAULT_WIRESERVER = "168.63.129.16"

BASE_HEADERS = {
    "x-ms-agent-name": "WALinuxAgent",
    "x-ms-version": "2012-11-30",
}

def http_get(url: str, headers: dict, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()

def generate_transport_cert(tmpdir: str):
    """Create the LinuxTransport self-signed cert/key Azure expects."""
    priv = os.path.join(tmpdir, "TransportPrivate.pem")
    cert = os.path.join(tmpdir, "TransportCert.pem")
    subprocess.run(
        [
            "openssl","req","-x509","-nodes",
            "-subj","/CN=LinuxTransport",
            "-days","32768",
            "-newkey","rsa:3072",
            "-keyout",priv,
            "-out",cert,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Azure header wants the cert as a single line without the BEGIN/END lines.
    with open(cert, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if "CERTIFICATE" not in ln]
    one_line_cert = "".join(lines)
    return priv, cert, one_line_cert

def parse_certificates_url(goalstate_xml: bytes, endpoint_host: str) -> str:
    root = ET.fromstring(goalstate_xml)
    el = root.find("./Container/RoleInstanceList/RoleInstance/Configuration/Certificates")
    if el is None or not el.text:
        raise RuntimeError("Certificates URL not found in GoalState XML.")
    url = el.text.strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url
    # Fallback if a relative path is returned (rare).
    return f"http://{endpoint_host}/{url.lstrip('/')}"

def decrypt_pkcs7_to_pem_bundle(certificates_xml: bytes, tmpdir: str, priv: str, cert: str) -> bytes:
    """
    certificates_xml contains a <Data> element with base64 PKCS#7.
    We wrap it in a MIME envelope and pipe through openssl to decrypt and emit a PEM bundle.
    """
    root = ET.fromstring(certificates_xml)
    data_el = root.find(".//Data")
    if data_el is None or not data_el.text:
        raise RuntimeError("No <Data> payload found in certificates XML.")

    mime_lines = [
        b"MIME-Version: 1.0",
        b'Content-Disposition: attachment; filename="Certificates.p7m"',
        b'Content-Type: application/x-pkcs7-mime; name="Certificates.p7m"',
        b"Content-Transfer-Encoding: base64",
        b"",
        data_el.text.encode("utf-8"),
    ]
    mime_blob = b"\n".join(mime_lines)

    # Decrypt PKCS#7 using our key/cert, then dump PKCS#12 contents as PEMs.
    cmd = (
        f"openssl cms -decrypt -in /dev/stdin -inkey {priv} -recip {cert} "
        f"| openssl pkcs12 -nodes -password pass:"
    )
    out = subprocess.run(
        cmd,
        shell=True,
        input=mime_blob,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    return out

def pretty_print_xml(xml_bytes: bytes, label: str):
    try:
        import xml.dom.minidom
        # Normalize line endings and remove excessive blank lines
        xml_str = xml_bytes.decode(errors="ignore").replace('\r', '')
        dom = xml.dom.minidom.parseString(xml_str)
        pretty = dom.toprettyxml()
        # Remove consecutive blank lines
        pretty = '\n'.join([line for line in pretty.splitlines() if line.strip()])
        print(f"\n--- {label} ---")
        print(pretty)
    except Exception as e:
        print(f"Could not pretty-print {label}: {e}")
        print(xml_bytes.decode(errors="ignore"))

def extract_ssh_keys_from_pem_bundle(pem_bundle: bytes) -> list[str]:
    """
    From a PEM bundle that includes multiple CERTIFICATE blocks (and possibly keys),
    convert each certificate's public key to OpenSSH format.
    """
    keys = []
    cert_block = []
    for raw in pem_bundle.splitlines():
        line = raw.decode("utf-8", "ignore")
        cert_block.append(line)
        if line.strip().startswith("-----END CERTIFICATE-----"):
            cert_pem = "\n".join(cert_block).encode("utf-8")
            # Print X.509 cert details
            details_proc = subprocess.run([
                "openssl", "x509", "-text", "-noout"
            ], input=cert_pem, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("X.509 Certificate Details:\n", details_proc.stdout.decode())
            # Print fingerprint
            fp_proc = subprocess.run([
                "openssl", "x509", "-fingerprint", "-noout"
            ], input=cert_pem, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("Fingerprint:", fp_proc.stdout.decode().strip())
            # Get the public key (PKCS#8) from the cert…
            proc = subprocess.run(
                ["openssl", "x509", "-pubkey"],
                input=cert_pem,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            pubkey = proc.stdout
            # …and convert to OpenSSH format.
            ssh = subprocess.run(
                ["ssh-keygen", "-i", "-m", "PKCS8", "-f", "/dev/stdin"],
                input=pubkey,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout.decode().strip()
            if ssh and ssh not in keys:
                keys.append(ssh)
                # Print OpenSSH key fingerprint
                fp_proc = subprocess.run([
                    "ssh-keygen", "-lf", "/dev/stdin"
                ], input=ssh.encode(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("OpenSSH Key Fingerprint:", fp_proc.stdout.decode().strip())
            cert_block = []
        elif line.strip().startswith("-----END") and "KEY" in line:
            cert_block = []
    return keys

def main():
    endpoint = os.environ.get("AZURE_WIRESERVER", DEFAULT_WIRESERVER)
    goalstate_url = f"http://{endpoint}/machine/?comp=goalstate"
    with tempfile.TemporaryDirectory() as tmp:
        # 1) Fetch GoalState
        goalstate = http_get(goalstate_url, BASE_HEADERS)
        pretty_print_xml(goalstate, "GoalState XML")
        # 2) Extract Certificates URL
        certs_url = parse_certificates_url(goalstate, endpoint)
        # 3) Create transport cert and add secure headers
        priv, cert, cert_header = generate_transport_cert(tmp)
        secure_headers = dict(BASE_HEADERS)
        secure_headers.update({
            "x-ms-cipher-name": "DES_EDE3_CBC",
            "x-ms-guest-agent-public-x509-cert": cert_header,
        })
        # 4) Fetch certificates XML
        certs_xml = http_get(certs_url, secure_headers)
        pretty_print_xml(certs_xml, "Certificates XML")
        # 5) Decrypt PKCS#7 -> PEM bundle
        pem_bundle = decrypt_pkcs7_to_pem_bundle(certs_xml, tmp, priv, cert)
        # 6) Convert certs -> OpenSSH keys
        ssh_keys = extract_ssh_keys_from_pem_bundle(pem_bundle)

    if not ssh_keys:
        print("No SSH keys found.", file=sys.stderr)
        sys.exit(1)

    # Print one per line
    for k in ssh_keys:
        print(k)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

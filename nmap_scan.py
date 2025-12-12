#!/usr/bin/env python3
import subprocess
import pathlib
import xml.etree.ElementTree as ET
import json
import re
from datetime import datetime
import sys
import socket
import ssl
import time
import tempfile
import os



def run_nmap(target, prefix):
    cmd = [
        "nmap", "-sV",
        "-p", "80,443",
        "--script=vulners",
        "-T4",
        "-oA", prefix,
        target
    ]
    print("[+] Running nmap")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def parse_vulners_output(text, min_score=7.0, min_year=2018):
    items = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m_cve = re.search(r"(CVE-(\d{4})-\d+)", line)
        if not m_cve:
            continue

        cve_id = m_cve.group(1)
        year = int(m_cve.group(2))

        m_score = re.search(r"(\d+\.\d+)", line)
        m_url = re.search(r"(https?://\S+)", line)
        if not m_score or not m_url:
            continue

        score = float(m_score.group(1))
        url = m_url.group(1)

        if score < min_score or year < min_year:
            continue
        if cve_id in seen:
            continue

        seen.add(cve_id)
        items.append({"id": cve_id, "score": score, "url": url, "year": year})

    items.sort(key=lambda x: (x["score"], x["year"]), reverse=True)
    return items



_TLS_TIMEOUT = 6.0


def _as_iso_utc(epoch_seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_seconds))


def simple_tls_info(host: str, port: int = 443):

    out = {
        "target": f"{host}:{port}",
        "ok": False,
        "tls_version": None,
        "cipher": None,
        "cert": {
            "not_before": None,
            "not_after": None,
            "days_left": None,
        },
        "error": None,
    }

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  

        with socket.create_connection((host, port), timeout=_TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:  
                out["ok"] = True
                out["tls_version"] = ssock.version()  
                c = ssock.cipher()                    
                out["cipher"] = c[0] if c else None

                der = ssock.getpeercert(binary_form=True)  
                if der:
                    pem = ssl.DER_cert_to_PEM_cert(der)    


                    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
                        f.write(pem)
                        tmp_path = f.name

                    try:
                        info = ssl._ssl._test_decode_cert(tmp_path)
                        nb = info.get("notBefore")
                        na = info.get("notAfter")

                        if nb:
                            nb_s = ssl.cert_time_to_seconds(nb)  
                            out["cert"]["not_before"] = _as_iso_utc(nb_s)

                        if na:
                            na_s = ssl.cert_time_to_seconds(na)  
                            out["cert"]["not_after"] = _as_iso_utc(na_s)
                            out["cert"]["days_left"] = int((na_s - int(time.time())) // 86400)

                    finally:
                        try:
                            os.unlink(tmp_path)
                        except Exception:
                            pass

    except Exception as e:
        out["error"] = str(e)

    return out



_HTTP_TIMEOUT = 8


def simple_security_headers(host: str):

    out = {
        "url": f"https://{host}/",
        "ok": False,
        "status_code": None,
        "error": None,
        "headers": {
            "X-Frame-Options": None,
            "Content-Security-Policy": None,
            "Strict-Transport-Security": None,
        }
    }

    try:
        import requests
    except Exception:
        out["error"] = "requests not installed (pip install requests)"
        return out

    try:
        r = requests.get(out["url"], timeout=_HTTP_TIMEOUT, allow_redirects=True, verify=False)
        out["ok"] = True
        out["url"] = r.url
        out["status_code"] = r.status_code
        out["headers"]["X-Frame-Options"] = r.headers.get("X-Frame-Options")
        out["headers"]["Content-Security-Policy"] = r.headers.get("Content-Security-Policy")
        out["headers"]["Strict-Transport-Security"] = r.headers.get("Strict-Transport-Security")
    except Exception as e:
        out["error"] = str(e)

    return out



def parse_xml(xml_path, target: str | None = None, do_tls=True, do_headers=True):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts_out = []

    for host in root.findall("host"):
        hobj = {"addresses": [], "ports": []}

        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                hobj["addresses"].append(addr.get("addr"))

        for port in host.findall(".//port"):
            state = port.find("state")
            service = port.find("service")
            scripts = port.findall("script")

            port_info = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state.get("state") if state is not None else "",
                "service": None,
                "version": None,
                "vulnerabilities": []
            }

            if service is not None:
                port_info["service"] = service.get("product") or service.get("name")
                ver = service.get("version")
                if ver:
                    port_info["version"] = ver

            for s in scripts:
                if s.get("id") == "vulners" and s.get("output"):
                    port_info["vulnerabilities"] = parse_vulners_output(s.get("output"))

            hobj["ports"].append(port_info)

        hosts_out.append(hobj)

    out = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "hosts": hosts_out
    }

    if not target:
        try:
            target = hosts_out[0]["addresses"][0]
        except Exception:
            target = None

    if target and do_tls:
        out["tls"] = simple_tls_info(target, 443)

    if target and do_headers:
        out["http_headers"] = simple_security_headers(target)

    return out



def main():
    try:
        target = input("Target (ip/host) [default: scanme.nmap.org]: ").strip() or "scanme.nmap.org"
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        sys.exit(1)

    pathlib.Path("scans").mkdir(exist_ok=True)
    safe_name = target.replace(":", "_").replace("/", "_")
    prefix = f"scans/{safe_name}-vuln"

    try:
        run_nmap(target, prefix)
    except FileNotFoundError:
        print("nmap not found. Install nmap.")
        sys.exit(2)
    except subprocess.CalledProcessError:
        print("nmap finished with warnings, continuing…")

    xml_file = prefix + ".xml"
    json_file = f"scans/{safe_name}-clean.json"
    if not pathlib.Path(xml_file).exists():
        print("XML not found:", xml_file)
        sys.exit(3)

    data = parse_xml(xml_file, target=target, do_tls=True, do_headers=True)

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Clean JSON saved to {json_file}")


if __name__ == "__main__":
    main()

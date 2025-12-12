import html
from datetime import datetime


def build_full_html_report(target, scan_data, ai_result, raw_text=None) -> str:

    if not isinstance(scan_data, dict):
        scan_data = {}
    if not isinstance(ai_result, dict):
        ai_result = {}

    recs = ai_result.get("recommendations")
    if not isinstance(recs, list):
        recs = []
        ai_result["recommendations"] = recs

    now = datetime.utcnow().isoformat() + "Z"
    hosts = scan_data.get("hosts", []) or []
    host_addr = hosts[0].get("addresses", [target])[0] if hosts else target

    tls = scan_data.get("tls") or {}
    http_headers = scan_data.get("http_headers") or {}

    try:
        with open("styles.css", "r", encoding="utf-8") as f:
            css_content = f.read()
    except FileNotFoundError:
        css_content = """
        :root{
          --bg:#0f1724;
          --card:#0b1220;
          --accent:#4fd1c5;
          --muted:#93a3b8;
          --danger:#ff6b6b;
          --glass: rgba(255,255,255,0.03);
        }
        html,body{height:100%;margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial;background:linear-gradient(180deg,#071226 0%, #081826 60%);color:#e6eef6}
        .wrap{max-width:960px;margin:28px auto;padding:20px}
        header{display:flex;align-items:center;gap:16px}
        h1{font-size:20px;margin:0}
        .meta{color:var(--muted);font-size:13px}
        .grid{display:grid;grid-template-columns:1fr 360px;gap:18px;margin-top:18px}
        .card{background:var(--card);border-radius:12px;padding:16px;box-shadow:0 6px 28px rgba(3,6,12,0.6);border:1px solid rgba(255,255,255,0.03)}
        .services li{margin:8px 0;padding:10px;background:var(--glass);border-radius:8px;list-style:none}
        .vuln{margin:10px 0;padding:12px;border-radius:10px;background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0.01));border-left:4px solid rgba(255,255,255,0.04)}
        .priority-high{color:var(--danger);font-weight:700}
        .priority-med{color:#f6c85f;font-weight:700}
        .priority-low{color:#8bd5ff;font-weight:700}
        .badge{display:inline-block;padding:6px 10px;border-radius:999px;background:rgba(255,255,255,0.03);color:var(--muted);font-size:12px}
        .steps{background:rgba(255,255,255,0.02);padding:10px;border-radius:8px;margin-top:8px}
        pre{background:#071025;padding:12px;border-radius:8px;overflow:auto;color:#cfeef0}
        footer{margin-top:14px;color:var(--muted);font-size:13px}
        """

    def _yesno(v: bool) -> str:
        return "yes" if v else "no"

    def _kv_list(title: str, kv):
        html_parts.append(f"<div class='steps'><b>{html.escape(str(title))}:</b><ul>")
        for k, v in kv:
            html_parts.append(f"<li><b>{html.escape(str(k))}</b>: {html.escape(str(v))}</li>")
        html_parts.append("</ul></div>")

    html_parts = [
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Audit report {html.escape(target)}</title><style>{css_content}</style></head><body>",
        "<div class='wrap'>",
        "<header>",
        f"<div><h1>Отчёт аудита безопасности — {html.escape(target)}</h1><div class='meta'>Сформирован: {now}</div></div>",
        "</header>",
    ]

    html_parts.append("<div class='grid'>")

    html_parts.append("<div class='card'>")
    html_parts.append("<h3>Общая информация</h3>")
    html_parts.append(f"<p><b>Адрес:</b> {html.escape(str(host_addr))}</p>")

    if hosts:
        html_parts.append("<p><b>Сервисы:</b></p><ul class='services'>")
        for p in (hosts[0].get("ports", []) or []):
            svc = html.escape(str(p.get("service") or "Неизвестный сервис"))
            ver = html.escape(str(p.get("version") or "-"))
            state = html.escape(str(p.get("state") or "-"))
            port_num = html.escape(str(p.get("port")))
            html_parts.append(
                f"<li>Порт <b>{port_num}</b> — {svc} <span class='badge'>{ver}</span> — {state}</li>"
            )
        html_parts.append("</ul>")
    else:
        html_parts.append("<p>Сервисы не обнаружены.</p>")

    html_parts.append("<hr style='border:none;height:1px;background:rgba(255,255,255,0.03);margin:12px 0'>")
    html_parts.append("<h3>SSL / HTTPS</h3>")

    if not tls:
        html_parts.append("<p>Данные TLS отсутствуют.</p>")
    elif isinstance(tls, dict) and tls.get("error"):
        html_parts.append(f"<p>Ошибка TLS-аудита: <code>{html.escape(str(tls.get('error')))}</code></p>")
    else:
        if isinstance(tls, dict) and (tls.get("tls_version") or tls.get("cipher")):
            html_parts.append(f"<p><b>TLS версия:</b> {html.escape(str(tls.get('tls_version')))}</p>")
            html_parts.append(f"<p><b>Cipher:</b> {html.escape(str(tls.get('cipher')))}</p>")

            cert = (tls.get("cert") or {}) if isinstance(tls.get("cert"), dict) else {}
            na = cert.get("not_after")
            dl = cert.get("days_left")
            if na:
                html_parts.append(f"<p><b>Действует до:</b> {html.escape(str(na))} "
                                  f"(days_left={html.escape(str(dl))})</p>")
        else:
            validation = (tls.get("validation") or {}) if isinstance(tls, dict) else {}
            cert = (tls.get("cert") or {}) if isinstance(tls, dict) else {}
            protocols = (tls.get("protocols") or {}) if isinstance(tls, dict) else {}
            ciphers = (tls.get("ciphers_supported") or []) if isinstance(tls, dict) else []

            html_parts.append(f"<p><b>Цепочка сертификатов валидна:</b> {html.escape(str(validation.get('chain_ok')))}</p>")
            if validation.get("error"):
                html_parts.append(f"<p><b>Ошибка валидации:</b> <code>{html.escape(str(validation.get('error')))}</code></p>")

            if isinstance(cert, dict) and cert:
                html_parts.append(f"<p><b>Действует до:</b> {html.escape(str(cert.get('not_after')))} "
                                  f"(days_left={html.escape(str(cert.get('days_left')))})</p>")
                html_parts.append(f"<p><b>Просрочен:</b> {html.escape(str(cert.get('expired')))}</p>")

                sans = cert.get("subject_alt_names") or []
                if sans:
                    html_parts.append("<div class='steps'><b>SAN (DNS):</b><ul>")
                    for s in sans[:12]:
                        html_parts.append(f"<li>{html.escape(str(s))}</li>")
                    html_parts.append("</ul></div>")

            if isinstance(protocols, dict) and protocols:
                _kv_list("Поддержка TLS-протоколов", [(k, _yesno(bool(v))) for k, v in protocols.items()])

            if isinstance(ciphers, list) and ciphers:
                html_parts.append("<div class='steps'><b>Шифры (sample, TLS 1.2):</b><ul>")
                for c in ciphers[:14]:
                    html_parts.append(f"<li>{html.escape(str(c))}</li>")
                html_parts.append("</ul></div>")

    html_parts.append("<hr style='border:none;height:1px;background:rgba(255,255,255,0.03);margin:12px 0'>")
    html_parts.append("<h3>Заголовки безопасности</h3>")

    if not http_headers:
        html_parts.append("<p>Данные по HTTP-заголовкам отсутствуют.</p>")
    elif isinstance(http_headers, dict) and http_headers.get("error"):
        html_parts.append(f"<p>Ошибка проверки заголовков: <code>{html.escape(str(http_headers.get('error')))}</code></p>")
    else:
 
        if isinstance(http_headers, dict) and "final_url" in http_headers:
            html_parts.append(f"<p><b>URL:</b> {html.escape(str(http_headers.get('final_url')))}</p>")
            html_parts.append(f"<p><b>Status:</b> {html.escape(str(http_headers.get('status_code')))}</p>")

            hdrs = http_headers.get("headers") or {}
            html_parts.append("<div class='steps'><b>Результаты:</b><ul>")
            for name in ("X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"):
                obj = (hdrs.get(name) or {}) if isinstance(hdrs, dict) else {}
                present = bool(obj.get("present"))
                value = obj.get("value")
                if present and value:
                    html_parts.append(f"<li><b>{html.escape(name)}:</b> present — {html.escape(str(value))}</li>")
                else:
                    html_parts.append(f"<li><b>{html.escape(name)}:</b> missing</li>")
            html_parts.append("</ul></div>")
        else:
            html_parts.append(f"<p><b>URL:</b> {html.escape(str(http_headers.get('url')))}</p>")
            html_parts.append(f"<p><b>Status:</b> {html.escape(str(http_headers.get('status_code')))}</p>")

            hdrs = http_headers.get("headers") or {}
            html_parts.append("<div class='steps'><b>Результаты:</b><ul>")
            for name in ("X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"):
                val = hdrs.get(name) if isinstance(hdrs, dict) else None
                if val:
                    html_parts.append(f"<li><b>{html.escape(name)}:</b> present — {html.escape(str(val))}</li>")
                else:
                    html_parts.append(f"<li><b>{html.escape(name)}:</b> missing</li>")
            html_parts.append("</ul></div>")


    html_parts.append("<hr style='border:none;height:1px;background:rgba(255,255,255,0.03);margin:12px 0'>")

    recs = ai_result.get("recommendations") or []
    recs = [r for r in recs if isinstance(r, dict)]

    if recs:
        html_parts.append("<h3>Уязвимости и рекомендации</h3>")
        for rec in recs:
            pr = rec.get("priority", "Unknown")
            pr_cls = "priority-low"
            if str(pr).lower() == "high":
                pr_cls = "priority-high"
            elif str(pr).lower() == "medium":
                pr_cls = "priority-med"

            html_parts.append("<div class='vuln'>")
            html_parts.append(
                f"<div><b>{html.escape(str(rec.get('id','Без ID')))}</b> — "
                f"<span class='{pr_cls}'>{html.escape(str(pr))}</span></div>"
            )

            if rec.get("title"):
                html_parts.append(f"<div><b>Название:</b> {html.escape(str(rec.get('title')))}</div>")

            html_parts.append(f"<p style='margin-top:8px'>{html.escape(str(rec.get('risk','')))}</p>")

            steps = rec.get("steps") or []
            if isinstance(steps, list) and steps:
                html_parts.append("<div class='steps'><b>Устранение:</b><ol>")
                for s in steps:
                    html_parts.append(f"<li>{html.escape(str(s))}</li>")
                html_parts.append("</ol></div>")

            verify = rec.get("verify") or []
            if isinstance(verify, list) and verify:
                html_parts.append("<div style='margin-top:8px'><b>Проверка:</b><ol>")
                for v in verify:
                    html_parts.append(f"<li>{html.escape(str(v))}</li>")
                html_parts.append("</ol></div>")

            refs = rec.get("references") or []
            if isinstance(refs, list) and refs:
                html_parts.append("<div style='margin-top:8px'><b>Ссылки:</b><ul>")
                for r in refs:
                    html_parts.append(
                        f"<li><a href='{html.escape(str(r))}' target='_blank'>{html.escape(str(r))}</a></li>"
                    )
                html_parts.append("</ul></div>")

            html_parts.append("</div>")
    else:
        if raw_text:
            html_parts.append("<h3>AI: сырой текст (не удалось распарсить JSON)</h3>")
            html_parts.append(f"<pre>{html.escape(str(raw_text))}</pre>")
        else:
            html_parts.append("<h3>Результаты анализа отсутствуют</h3>")

    html_parts.append("</div>")  # end left card

  
    html_parts.append("<div class='card'>")
    html_parts.append("<h3>Краткое резюме</h3>")

    recs = ai_result.get("recommendations") or []
    recs = [r for r in recs if isinstance(r, dict)]

    if recs:
        total = len(recs)
        high = sum(1 for r in recs if (r.get("priority") or "").lower() == "high")
        med = sum(1 for r in recs if (r.get("priority") or "").lower() == "medium")
        low = total - high - med

        html_parts.append(f"<p>Всего найдено: <b>{total}</b></p>")
        html_parts.append(
            f"<p>High: <b class='priority-high'>{high}</b> &nbsp; "
            f"Medium: <b class='priority-med'>{med}</b> &nbsp; "
            f"Low: <b class='priority-low'>{low}</b></p>"
        )
    else:
        html_parts.append("<p>Нет рекомендаций от AI</p>")

    html_parts.append("<hr style='border:none;height:1px;background:rgba(255,255,255,0.03);margin:12px 0'>")

    if isinstance(tls, dict) and not tls.get("error"):
        if tls.get("tls_version") or tls.get("cipher"):
            html_parts.append(
                "<p class='meta'><b>TLS:</b> " +
                f"version={html.escape(str(tls.get('tls_version')))}, " +
                f"cipher={html.escape(str(tls.get('cipher')))}" +
                "</p>"
            )
        else:
            cert = tls.get("cert") or {}
            protocols = tls.get("protocols") or {}
            h_tls12 = bool(protocols.get("TLSv1.2")) if isinstance(protocols, dict) else False
            h_tls13 = bool(protocols.get("TLSv1.3")) if isinstance(protocols, dict) else False
            html_parts.append(
                "<p class='meta'><b>TLS:</b> " +
                f"TLS1.2={html.escape(_yesno(h_tls12))}, TLS1.3={html.escape(_yesno(h_tls13))}, " +
                f"expired={html.escape(str((cert or {}).get('expired')))}" +
                "</p>"
            )

    if isinstance(http_headers, dict) and not http_headers.get("error"):
        hdrs = http_headers.get("headers") or {}
        missing = []
        for name in ("X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"):
            if isinstance(hdrs, dict):
                v = hdrs.get(name)
                if isinstance(v, dict):
                    if not v.get("present"):
                        missing.append(name)
                else:
                    if not v:
                        missing.append(name)

    html_parts.append("</div>")  

    html_parts.append("</div>")  
    html_parts.append(f"<footer><small>Сформирован: {now}</small></footer>")
    html_parts.append("</div></body></html>")

    return "\n".join(html_parts)

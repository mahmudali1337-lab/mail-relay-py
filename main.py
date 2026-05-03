import asyncio
import base64
import json
import logging
import os
import smtplib
import sys
import threading
import time
import uuid
from pathlib import Path

import dkim
import dns.resolver
import yaml
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)

_queue_dir = "/var/spool/mailrelay"


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def dkim_sign(data: bytes, mail_from: str, domains: list) -> bytes:
    domain = mail_from.split("@")[-1] if "@" in mail_from else ""
    for d in domains:
        if d.get("domain") == domain:
            try:
                with open(d["dkim_key"], "rb") as f:
                    key = f.read()
                sig = dkim.sign(
                    data,
                    d["selector"].encode(),
                    domain.encode(),
                    key,
                    canonicalize=(b"relaxed", b"relaxed"),
                    include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
                )
                log.info(f"dkim signed selector={d['selector']}")
                return sig + data
            except Exception as e:
                log.error(f"dkim sign failed: {e}")
    return data


def enqueue(mail_from: str, rcpt_tos: list, data: bytes):
    job = {
        "id": str(uuid.uuid4()),
        "from": mail_from,
        "to": rcpt_tos,
        "data": base64.b64encode(data).decode(),
        "created": time.time(),
        "attempts": 0,
        "next_try": time.time(),
    }
    path = Path(_queue_dir) / f'{job["id"]}.json'
    path.write_text(json.dumps(job))
    log.info(f'enqueued id={job["id"]} from={mail_from} to={rcpt_tos} size={len(data)}')


def deliver_job(cfg: dict, job: dict):
    data = base64.b64decode(job["data"])
    servers = cfg.get("servers", [])
    hostname = cfg.get("hostname", "mail.dstat.coffee")

    src_ip = servers[job["attempts"] % len(servers)] if servers else None

    for rcpt in job["to"]:
        domain = rcpt.split("@")[-1]
        log.info(f"resolving MX for {domain}")
        try:
            answers = dns.resolver.resolve(domain, "MX")
        except Exception as e:
            log.error(f"MX lookup failed for {domain}: {e}")
            raise
        mx_list = sorted(answers, key=lambda r: r.preference)

        last_err = None
        for mx in mx_list:
            host = str(mx.exchange).rstrip(".")
            try:
                log.info(f"connecting to {host}:25 src={src_ip}")
                src = (src_ip, 0) if src_ip else None
                smtp = smtplib.SMTP(host, 25, timeout=30, source_address=src)
                smtp.ehlo(hostname)
                smtp.mail(job["from"])
                smtp.rcpt(rcpt)
                smtp.data(data)
                smtp.quit()
                log.info(f'delivered id={job["id"]} to={rcpt} via={host}')
                last_err = None
                break
            except Exception as e:
                log.error(f"delivery to {host} failed: {e}")
                last_err = e
        if last_err:
            raise last_err


def worker_loop(cfg: dict, queue_dir: str):
    retry_max = cfg.get("retry_max", 10)
    while True:
        try:
            for f in Path(queue_dir).glob("*.json"):
                try:
                    job = json.loads(f.read_text())
                except Exception:
                    continue
                if job.get("next_try", 0) > time.time():
                    continue
                job["attempts"] += 1
                try:
                    deliver_job(cfg, job)
                    f.unlink(missing_ok=True)
                except Exception as e:
                    if job["attempts"] >= retry_max:
                        log.error(f'giving up id={job["id"]}: {e}')
                        f.rename(str(f) + ".failed")
                    else:
                        delay = min(300, 30 * (2 ** (job["attempts"] - 1)))
                        job["next_try"] = time.time() + delay
                        f.write_text(json.dumps(job))
                        log.info(f'retry id={job["id"]} in {delay}s attempt={job["attempts"]}')
        except Exception as e:
            log.error(f"worker error: {e}")
        time.sleep(10)


class SMTPHandler:
    def __init__(self, cfg):
        self.cfg = cfg

    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos = list(envelope.rcpt_tos)
        data = envelope.content
        if isinstance(data, str):
            data = data.encode()
        data = dkim_sign(data, mail_from, self.cfg.get("domains", []))
        enqueue(mail_from, rcpt_tos, data)
        return "250 Message accepted"


def make_authenticator(password: str):
    async def authenticator(server, session, envelope, mechanism, auth_data):
        if mechanism != "PLAIN":
            return AuthResult(success=False, handled=True)
        try:
            if isinstance(auth_data, str):
                auth_data = auth_data.encode()
            parts = auth_data.split(b"\x00")
            pwd = parts[2] if len(parts) >= 3 else parts[1]
            if pwd.decode() == password:
                return AuthResult(success=True)
        except Exception as e:
            log.error(f"auth error: {e}")
        return AuthResult(success=False, handled=True)

    return authenticator


def main():
    global _queue_dir

    path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    cfg = load_config(path)

    _queue_dir = cfg.get("queue_dir", "/var/spool/mailrelay")
    os.makedirs(_queue_dir, exist_ok=True)

    listen = cfg.get("listen", ":587")
    if listen.startswith(":"):
        host, port = "0.0.0.0", int(listen[1:])
    else:
        h, p = listen.rsplit(":", 1)
        host, port = h, int(p)

    hostname = cfg.get("hostname", "mail.dstat.coffee")
    password = cfg.get("password", "")
    workers_count = cfg.get("workers", 5)

    handler = SMTPHandler(cfg)
    auth_fn = make_authenticator(password)

    controller = Controller(
        handler,
        hostname=host,
        port=port,
        server_hostname=hostname,
        auth_required=True,
        auth_require_tls=False,
        authenticator=auth_fn,
    )

    for _ in range(workers_count):
        t = threading.Thread(target=worker_loop, args=(cfg, _queue_dir), daemon=True)
        t.start()

    controller.start()
    log.info(f"smtp relay listening on {host}:{port} hostname={hostname}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    main()

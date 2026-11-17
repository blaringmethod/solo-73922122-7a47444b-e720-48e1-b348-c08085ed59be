"""Local IMAP demonstration source: a minimal IMAP4rev1 server over a Maildir.

Purpose: make Docker Compose a self-contained demonstration of the collection
rules (SP2/SP3-style behaviour).  It implements just enough IMAP for the
collector and the web UI:

* ``CAPABILITY``, ``LOGIN``, ``LOGOUT``, ``NOOP``, ``SELECT``/``EXAMINE``,
  ``STATUS``, ``UID SEARCH``, ``UID FETCH``, ``UID STORE``;
* UIDVALIDITY and UIDNEXT are real and persist across restarts;
* messages are byte-preserving end to end: delivery stores the exact RFC822
  bytes it was given (CRLF, folded headers, MIME boundaries untouched),
  ``FETCH`` serves the file verbatim, and flag changes only rename the
  Maildir file — so the SHA-256 of a downloaded original always equals the
  SHA-256 of the delivered bytes;
* ``GET /`` shows a small HTML console, ``POST /ctl/*`` drives the demo:
  deliver a message, rebuild the mailbox (new UIDVALIDITY, UIDs restart at 1),
  make the next ``UID STORE`` succeed and then drop the connection before
  replying, and inspect flags.

This server is for demonstration only.  It is not intended to be exposed to an
untrusted network.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import secrets
import socketserver
import threading
import time
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default as default_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# Maildir info-letter for each IMAP system flag the demo understands.  Flags
# live in the file name (``cur/<uniq>:2,FLAGS``), which is why marking a
# message never has to touch its bytes.
_FLAG_TO_LETTER = {
    "\\Answered": "R",
    "\\Deleted": "T",
    "\\Draft": "D",
    "\\Flagged": "F",
    "\\Seen": "S",
}
_LETTER_TO_FLAG = {letter: flag for flag, letter in _FLAG_TO_LETTER.items()}


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass
class MailboxStore:
    """Maildir-backed mailbox with stable UID bookkeeping.

    The store is byte-preserving end to end:

    * ``deliver`` writes the exact RFC822 bytes it received — nothing is
      parsed and re-serialised, so CRLF line endings, folded headers and
      MIME boundaries survive intact;
    * ``message_by_uid`` reads the file back verbatim for ``FETCH``;
    * ``set_flag`` only renames the file (Maildir flags live in the file
      name), so marking ``\\Seen`` — immediately, on retry after a dropped
      connection, or after a restart — can never rewrite the message body.

    UIDs are attached to Maildir keys (filenames), not to positional indexes,
    so flag changes (which rename the file) and new deliveries never remap an
    existing UID.  ``rebuild`` deliberately starts a new UIDVALIDITY and
    renumbers every message from 1, which is what the real world looks like
    after a mailbox re-creation and what the collector must survive.
    """

    root: Path
    uidvalidity: int = 1
    uidnext: int = 1
    uid_map: dict[int, str] = field(default_factory=dict)      # uid -> maildir key
    key_uid: dict[str, int] = field(default_factory=dict)      # maildir key -> uid
    lock: threading.RLock = field(default_factory=threading.RLock)
    drop_next_store: bool = False
    store_count: int = 0
    _uniq_counter: int = 0

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._load()

    @property
    def meta_path(self) -> Path:
        return self.root / "demo-meta.json"

    @property
    def maildir(self) -> Path:
        return self.root / "maildir"

    # ------------------------------------------------------------ persistence
    def _load(self) -> None:
        for sub in ("cur", "new", "tmp"):
            (self.maildir / sub).mkdir(parents=True, exist_ok=True)
        if self.meta_path.exists():
            meta = json.loads(self.meta_path.read_text("utf-8"))
            self.uidvalidity = int(meta.get("uidvalidity", 1))
            self.uidnext = int(meta.get("uidnext", 1))
            self.uid_map = {int(k): str(v) for k, v in meta.get("uid_map", {}).items()}
            self.key_uid = {v: k for k, v in self.uid_map.items()}
        self._ensure_uids()
        self._flush()

    def _flush(self) -> None:
        payload = json.dumps(
            {
                "uidvalidity": self.uidvalidity,
                "uidnext": self.uidnext,
                "uid_map": {str(k): v for k, v in self.uid_map.items()},
            },
            indent=2,
        )
        tmp = self.meta_path.with_name(self.meta_path.name + ".tmp")
        tmp.write_text(payload, "utf-8")
        os.replace(tmp, self.meta_path)

    # ------------------------------------------------------------- maildir io
    def _scan_keys(self) -> list[str]:
        """All message keys: ``uniq`` in ``new/``, ``uniq:2,FLAGS`` in ``cur/``."""
        keys: list[str] = []
        for sub in ("cur", "new"):
            for entry in (self.maildir / sub).iterdir():
                if entry.is_file() and not entry.name.startswith("."):
                    keys.append(entry.name)
        return sorted(keys)

    def _key_path(self, key: str) -> Path:
        sub = "cur" if ":" in key else "new"
        path = self.maildir / sub / key
        if path.exists():
            return path
        # Tolerate layouts that keep flagless messages in cur/.
        for sub in ("cur", "new"):
            candidate = self.maildir / sub / key
            if candidate.exists():
                return candidate
        return path

    @staticmethod
    def _strip_flags(key: str) -> str:
        # Maildir keys are "unique:2,FLAGS"; compare only the unique part when
        # a flag update potentially renames a file.
        return key.split(":", 1)[0]

    @staticmethod
    def _letters_of_key(key: str) -> set[str]:
        info = key.split(":", 1)[1] if ":" in key else ""
        if not info.startswith("2,"):
            return set()
        return set(info[2:])

    @classmethod
    def _flags_of_key(cls, key: str) -> set[str]:
        return {
            _LETTER_TO_FLAG[letter]
            for letter in cls._letters_of_key(key)
            if letter in _LETTER_TO_FLAG
        }

    def _new_uniq(self) -> str:
        self._uniq_counter += 1
        return (
            f"{time.time_ns()}.{os.getpid()}.{self._uniq_counter}"
            f".{secrets.token_hex(4)}"
        )

    def _ensure_uids(self) -> None:
        with self.lock:
            keys = self._scan_keys()
            known = set(self.key_uid)
            stripped = {self._strip_flags(k) for k in known}
            for key in keys:
                if key in known:
                    continue
                base = self._strip_flags(key)
                match = next((k for k in known if self._strip_flags(k) == base), None)
                if match is not None:
                    uid = self.key_uid.pop(match)
                    self.key_uid[key] = uid
                    self.uid_map[uid] = key
                    known.discard(match)
                    known.add(key)
                    continue
                if base in stripped:
                    continue
                uid = self.uidnext
                self.uidnext += 1
                self.uid_map[uid] = key
                self.key_uid[key] = uid
                known.add(key)
                stripped.add(base)
            # Drop mappings whose file disappeared.
            for key in list(self.key_uid):
                if key not in keys:
                    uid = self.key_uid.pop(key)
                    self.uid_map.pop(uid, None)
            self._flush()

    def deliver(self, raw: bytes) -> int:
        """Store *exactly* the bytes received and return the assigned UID."""
        with self.lock:
            uniq = self._new_uniq()
            tmp_path = self.maildir / "tmp" / uniq
            with open(tmp_path, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.maildir / "new" / uniq)
            _fsync_dir(self.maildir / "new")
            self._ensure_uids()
            return self.key_uid[uniq]

    def message_by_uid(self, uid: int):
        """Return ``(key, raw_bytes, flags)``; the bytes are the file verbatim."""
        with self.lock:
            key = self.uid_map.get(uid)
            if key is None:
                return None
            try:
                raw = self._key_path(key).read_bytes()
            except FileNotFoundError:
                return None
            return key, raw, self._flags_of_key(key)

    def set_flag(self, uid: int, flag: str, add: bool = True) -> bool:
        """Add/remove a flag by *renaming* the file; content is never touched."""
        letter = _FLAG_TO_LETTER.get(flag)
        if letter is None:
            return False
        with self.lock:
            key = self.uid_map.get(uid)
            if key is None:
                return False
            path = self._key_path(key)
            if not path.exists():
                return False
            letters = self._letters_of_key(key)
            if add:
                letters.add(letter)
            else:
                letters.discard(letter)
            base = self._strip_flags(key)
            if letters:
                new_key = f"{base}:2,{''.join(sorted(letters))}"
                new_path = self.maildir / "cur" / new_key
            else:
                new_key = base
                new_path = self.maildir / "new" / new_key
            if new_path != path:
                os.replace(path, new_path)
                _fsync_dir(new_path.parent)
                _fsync_dir(path.parent)
            self._ensure_uids()
            return True

    def rebuild(self, purge: bool = False) -> dict[str, Any]:
        """Start a new mailbox generation: new UIDVALIDITY, UIDs from 1.

        With ``purge`` the maildir is emptied first; the next delivery then
        receives UID 1 in the new generation, which is exactly the UID-reuse
        scenario the collector must not confuse with the old message.
        """
        with self.lock:
            if purge:
                for sub in ("cur", "new", "tmp"):
                    directory = self.maildir / sub
                    for path in directory.glob("*"):
                        if path.is_file():
                            path.unlink()
                    _fsync_dir(directory)
            self.uidvalidity += 1
            self.uidnext = 1
            self.uid_map = {}
            self.key_uid = {}
            self._ensure_uids()
            return {
                "uidvalidity": self.uidvalidity,
                "messages": len(self.uid_map),
                "purged": purge,
            }

    def all_flags(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with self.lock:
            for uid in sorted(self.uid_map):
                key = self.uid_map[uid]
                try:
                    raw = self._key_path(key).read_bytes()
                except FileNotFoundError:
                    continue
                out.append(
                    {
                        "uid": uid,
                        "flags": sorted(self._flags_of_key(key)),
                        "subject": _subject_of(raw),
                    }
                )
        return out


def _subject_of(raw: bytes) -> str:
    """Best-effort Subject for the console; parsing never alters the file."""
    try:
        msg = message_from_bytes(raw, policy=default_policy)
        return str(msg.get("Subject", "") or "")
    except Exception:  # noqa: BLE001 - display only
        return ""


class IMAPSession(socketserver.StreamRequestHandler):
    server: "DemoServer"

    def setup(self) -> None:
        super().setup()
        self.selected = False
        self.store = self.server.store

    def handle(self) -> None:
        self._send(b"* OK [CAPABILITY IMAP4rev1 UIDPLUS] demo IMAP ready\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            try:
                if not self._dispatch(line.rstrip(b"\r\n")):
                    return
            except _DropConnection:
                try:
                    self.wfile.flush()
                except Exception:
                    pass
                self.connection.close()
                return

    def _send(self, data: bytes) -> None:
        self.wfile.write(data)
        self.wfile.flush()

    def _dispatch(self, line: bytes) -> bool:
        if not line:
            return True
        tag, rest = _split_tag(line)
        if tag is None:
            self._send(b"* BAD empty command\r\n")
            return True
        text = rest.decode("utf-8", "replace").strip()
        upper = text.upper()
        if upper.startswith("CAPABILITY"):
            self._send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n")
            self._send(tag + b" OK CAPABILITY done\r\n")
        elif upper.startswith("LOGIN"):
            self._send(tag + b" OK LOGIN done\r\n")
        elif upper.startswith("LOGOUT"):
            self._send(b"* BYE logging out\r\n")
            self._send(tag + b" OK LOGOUT done\r\n")
            return False
        elif upper.startswith("NOOP"):
            self._send(tag + b" OK NOOP done\r\n")
        elif upper.startswith("SELECT") or upper.startswith("EXAMINE"):
            self._cmd_select(tag, upper.startswith("EXAMINE"))
        elif upper.startswith("STATUS"):
            self._cmd_status(tag)
        elif upper.startswith("UID "):
            self._cmd_uid(tag, text[4:].strip())
        else:
            self._send(tag + b" BAD unknown command\r\n")
        return True

    def _cmd_select(self, tag: bytes, readonly: bool) -> None:
        flags = self.store.all_flags()
        self.selected = True
        self.readonly = readonly
        self._send(
            b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n"
            + b"* " + str(len(flags)).encode() + b" EXISTS\r\n"
            + b"* 0 RECENT\r\n"
            + b"* OK [UIDVALIDITY " + str(self.store.uidvalidity).encode() + b"] UIDs valid\r\n"
            + b"* OK [UIDNEXT " + str(self.store.uidnext).encode() + b"] Predicted next UID\r\n"
        )
        self._send(tag + b" OK [" + (b"READ-ONLY" if readonly else b"READ-WRITE") + b"] SELECT completed\r\n")

    def _cmd_status(self, tag: bytes) -> None:
        self.store._ensure_uids()
        flags = self.store.all_flags()
        unseen = sum(1 for f in flags if "\\Seen" not in f["flags"])
        uidnext = self.store.uidnext
        self._send(
            b'* STATUS "INBOX" (MESSAGES ' + str(len(flags)).encode()
            + b" UIDNEXT " + str(uidnext).encode()
            + b" UIDVALIDITY " + str(self.store.uidvalidity).encode()
            + b" UNSEEN " + str(unseen).encode() + b")\r\n"
        )
        self._send(tag + b" OK STATUS completed\r\n")

    def _cmd_uid(self, tag: bytes, text: str) -> None:
        parts = text.split(None, 2)
        if len(parts) < 2:
            self._send(tag + b" BAD UID needs a subcommand\r\n")
            return
        sub = parts[0].upper()
        if sub == "SEARCH":
            criteria = text.split(None, 1)[1].upper() if " " in text else "ALL"
            flags = self.store.all_flags()
            self.store._ensure_uids()
            uids = []
            for entry in flags:
                seen = "\\Seen" in entry["flags"]
                if "UNSEEN" in criteria and seen:
                    continue
                if criteria.strip() in {"ALL", "*"} or "UNSEEN" in criteria or "ALL" in criteria:
                    uids.append(str(entry["uid"]))
            self._send(b"* SEARCH " + " ".join(uids).encode() + b"\r\n")
            self._send(tag + b" OK SEARCH completed\r\n")
        elif sub == "FETCH":
            self._cmd_fetch(tag, parts[1], parts[2] if len(parts) > 2 else "(UID RFC822)")
        elif sub == "STORE":
            self._cmd_store(tag, parts[1], parts[2] if len(parts) > 2 else "")
        else:
            self._send(tag + b" BAD unsupported UID command\r\n")

    def _cmd_fetch(self, tag: bytes, uid_arg: str, spec: str) -> None:
        try:
            uid = int(uid_arg)
        except ValueError:
            self._send(b"* BAD UID must be numeric\r\n")
            self._send(tag + b" BAD FETCH\r\n")
            return
        found = self.store.message_by_uid(uid)
        if found is None:
            self._send(tag + b" OK FETCH completed\r\n")
            return
        _key, raw, flags = found
        flags_str = " ".join(sorted(flags)).encode()
        if "BODY.PEEK" in spec.upper() or "RFC822" in spec.upper():
            # The literal is the verbatim file content: what the collector
            # hashes and archives is exactly what was delivered.
            self._send(
                b"* 1 FETCH (UID " + str(uid).encode() + b" FLAGS (" + flags_str + b")"
                + b" BODY[] {" + str(len(raw)).encode() + b"}\r\n" + raw + b")\r\n"
            )
        else:
            self._send(b"* 1 FETCH (UID " + str(uid).encode() + b" FLAGS (" + flags_str + b"))\r\n")
        self._send(tag + b" OK FETCH completed\r\n")

    def _cmd_store(self, tag: bytes, uid_arg: str, spec: str) -> None:
        if getattr(self, "readonly", False):
            self._send(tag + b" NO mailbox is read-only\r\n")
            return
        try:
            uid = int(uid_arg)
        except ValueError:
            self._send(tag + b" BAD STORE\r\n")
            return
        if self.store.drop_next_store:
            self.store.drop_next_store = False
            # The flag is applied, but the client never sees the completion.
            self.store.set_flag(uid, "\\Seen", add=True)
            self.store.store_count += 1
            raise _DropConnection()
        ok = self.store.set_flag(uid, "\\Seen", add=True)
        self.store.store_count += 1
        if not ok:
            self._send(tag + b" NO no such message\r\n")
            return
        self._send(b"* 1 FETCH (UID " + str(uid).encode() + b" FLAGS (\\Seen))\r\n")
        self._send(tag + b" OK STORE completed\r\n")


class _DropConnection(Exception):
    pass


class DemoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, store: MailboxStore):
        self.store = store
        super().__init__(address, IMAPSession)


def _split_tag(line: bytes) -> tuple[bytes | None, bytes]:
    parts = line.split(b" ", 1)
    if len(parts) < 2:
        return None, b""
    return parts[0], parts[1]


# --------------------------------------------------------------------- control
def build_control_handler(store: MailboxStore, imap_port: int):
    class ControlHandler(BaseHTTPRequestHandler):
        server_version = "demo-imap-control"

        def log_message(self, fmt, *args):  # quieter logs
            pass

        def _json(self, payload: dict[str, Any], status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, body: str, status: int = 200) -> None:
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):  # noqa: N802
            path = urlparse(self.path).path
            if path == "/healthz":
                self._json({"ok": True, "uidvalidity": store.uidvalidity, "uidnext": store.uidnext})
                return
            if path == "/api/state":
                self._json(
                    {
                        "uidvalidity": store.uidvalidity,
                        "uidnext": store.uidnext,
                        "messages": store.all_flags(),
                        "drop_next_store": store.drop_next_store,
                        "stores": store.store_count,
                    }
                )
                return
            if path == "/":
                self._html(render_console(store, imap_port))
                return
            self._json({"error": "not found"}, 404)

        def do_POST(self):  # noqa: N802
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if path == "/ctl/deliver":
                payload = json.loads(body or b"{}")
                raw = build_demo_mail(payload)
                uid = store.deliver(raw)
                self._json(
                    {
                        "ok": True,
                        "uid": uid,
                        "uidvalidity": store.uidvalidity,
                        "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
                return
            if path == "/ctl/rebuild":
                payload = json.loads(body or b"{}")
                self._json({"ok": True, **store.rebuild(purge=bool(payload.get("purge", False)))})
                return
            if path == "/ctl/drop-store":
                payload = json.loads(body or b"{}")
                store.drop_next_store = bool(payload.get("enabled", True))
                self._json({"ok": True, "drop_next_store": store.drop_next_store})
                return
            if path == "/ctl/raw":
                # Byte-exact delivery: the request body *is* the RFC822
                # message.  The response echoes its SHA-256 so the caller
                # can verify the archived original against what was posted.
                uid = store.deliver(body)
                self._json(
                    {
                        "ok": True,
                        "uid": uid,
                        "uidvalidity": store.uidvalidity,
                        "bytes": len(body),
                        "sha256": hashlib.sha256(body).hexdigest(),
                    }
                )
                return
            self._json({"error": "not found"}, 404)

    return ControlHandler


def build_demo_mail(payload: dict[str, Any]) -> bytes:
    msg = EmailMessage()
    msg["From"] = payload.get("from", "lab@example.test")
    msg["To"] = payload.get("to", "warehouse@example.test")
    msg["Subject"] = payload.get("subject", "检验附件")
    msg["Date"] = payload.get("date", "Mon, 16 Nov 2026 09:00:00 +0000")
    msg.set_content("附件见下。\n")
    attachments = payload.get("attachments")
    if not attachments:
        attachments = [
            {
                "filename": "R001.csv",
                "report_no": "R001",
                "sample_no": "S001",
                "item": "ALT",
                "value": "12",
            }
        ]
    for spec in attachments:
        content = spec.get("content")
        if content is None:
            lines = ["报告号,样本号,项目,测值"]
            rows = spec.get("rows") or [spec]
            for row in rows:
                lines.append(
                    ",".join(
                        [
                            str(row.get("report_no", "R001")),
                            str(row.get("sample_no", "S001")),
                            str(row.get("item", "ALT")),
                            str(row.get("value", "12")),
                        ]
                    )
                )
            content = "\n".join(lines) + "\n"
        data = content.encode("utf-8") if isinstance(content, str) else content
        msg.add_attachment(
            data,
            maintype="text",
            subtype="csv",
            filename=spec.get("filename", "attachment.csv"),
        )
    return msg.as_bytes(policy=default_policy)


def render_console(store: MailboxStore, imap_port: int) -> str:
    messages = store.all_flags()
    rows = "\n".join(
        f"<tr><td>{m['uid']}</td><td>{html.escape(m['subject'])}</td>"
        f"<td>{html.escape(', '.join(m['flags']) or '—')}</td></tr>"
        for m in messages
    )
    return f"""<!doctype html>
<html lang="zh"><meta charset="utf-8"><title>IMAP 演示源</title>
<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.4rem}}
button{{margin:.2rem;padding:.4rem .8rem}}code{{background:#f3f3f3;padding:.1rem .3rem}}</style>
<h1>本地 IMAP 演示源</h1>
<p>IMAP 端口 <code>{imap_port}</code>，UIDVALIDITY <strong>{store.uidvalidity}</strong>，
UIDNEXT <strong>{store.uidnext}</strong>。“标记后断连”下一次 STORE：
<strong>{'开启' if store.drop_next_store else '关闭'}</strong>。</p>
<table><tr><th>UID</th><th>主题</th><th>Flags</th></tr>{rows}</table>
<h2>操作</h2>
<p>投递演示邮件、重建邮箱、开启标记后断连均可通过控制 API 完成，例如：</p>
<pre>curl -X POST localhost:8081/ctl/deliver -d '{{"subject":"演示"}}'
curl -X POST localhost:8081/ctl/rebuild
curl -X POST localhost:8081/ctl/drop-store -d '{{"enabled":true}}'</pre>
<p>完整演示流程见 <code>scripts/demo.sh</code>。</p>
</html>"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--imap-host", default="0.0.0.0")
    parser.add_argument("--imap-port", type=int, default=1143)
    parser.add_argument("--control-port", type=int, default=8081)
    parser.add_argument("--data", default="/demo-data")
    args = parser.parse_args()
    store = MailboxStore(Path(args.data))
    imap_server = DemoServer((args.imap_host, args.imap_port), store)
    threading.Thread(target=imap_server.serve_forever, daemon=True).start()
    control = ThreadingHTTPServer(("0.0.0.0", args.control_port), build_control_handler(store, args.imap_port))
    print(f"demo-imap listening imap={args.imap_port} control={args.control_port} data={args.data}", flush=True)
    control.serve_forever()


if __name__ == "__main__":
    main()

"""Byte fidelity of the demo source delivery/FETCH/mark chain.

The archivist posts a complete RFC822 message (CRLF line endings, folded
headers, base64 CSV attachment) to ``/ctl/raw``.  Every byte the collector
later archives must hash to exactly what was posted; marking ``\\Seen``,
retrying the mark after a dropped connection, and restarting the source must
never rewrite the original.  A rebuilt mailbox reusing UID 1 is collected as
a brand-new message whose archived bytes are the new delivery's bytes.
"""

from __future__ import annotations

import base64
import hashlib
import imaplib
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from app.collector import Collector
from app.config import Settings
from app.db import Database
from app.store import Store
from imap_demo.server import DemoServer, MailboxStore, build_control_handler

CSV = "报告号,样本号,项目,测值\r\nR900,S001,ALT,12\r\n".encode("utf-8")

# CRLF line endings, a folded Subject and a folded Content-Type, quoted-
# printable body, base64 CSV attachment: exactly the kind of message that
# re-serialisation used to mangle.
RAW = (
    b"From: Archivist <archivist@lab.example>\r\n"
    b"To: Warehouse <warehouse@lab.example>\r\n"
    b"Subject: =?utf-8?b?5qOA6rKM5qCH6KGo?=\r\n"
    b"\t R900 folded-tail\r\n"
    b"Date: Mon, 16 Nov 2026 09:00:00 +0000\r\n"
    b"Message-ID: <raw-fidelity-1@lab.example>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: multipart/mixed;\r\n"
    b"\tboundary=\"folded-boundary-xyz\"\r\n"
    b"\r\n"
    b"--folded-boundary-xyz\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: quoted-printable\r\n"
    b"\r\n"
    b"see attachment =E9=99=84=E4=BB=B6\r\n"
    b"--folded-boundary-xyz\r\n"
    b"Content-Type: text/csv; name=\"R900.csv\"\r\n"
    b"Content-Disposition: attachment; filename=\"R900.csv\"\r\n"
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n" + base64.encodebytes(CSV).replace(b"\n", b"\r\n") +
    b"--folded-boundary-xyz--\r\n"
)
RAW_SHA = hashlib.sha256(RAW).hexdigest()


def _make_collector(tmp_path: Path, port: int, instance: str = "inst-a") -> Collector:
    cfg = Settings(
        instance_id=instance,
        database_path=tmp_path / "db.sqlite3",
        storage_dir=tmp_path / "store",
        imap_host="127.0.0.1",
        imap_port=port,
        imap_user="lab",
        imap_password="lab-pass",
        account="lab@test",
        auto_scan_interval=0,
        scan_lease_seconds=60,
    )
    db = Database(cfg.database_path)
    db.init()
    store = Store(cfg.storage_dir)
    store.init()
    return Collector(cfg, db, store)


def _fetch_raw(port: int, uid: int) -> bytes:
    conn = imaplib.IMAP4("127.0.0.1", port)
    try:
        conn.login("lab", "lab-pass")
        conn.select("INBOX")
        typ, data = conn.uid("FETCH", str(uid), "(UID BODY.PEEK[])")
        assert typ == "OK"
        for item in data:
            if isinstance(item, tuple) and isinstance(item[1], bytes):
                return item[1]
        raise AssertionError("FETCH returned no literal")
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001 - best effort
            pass


@pytest.fixture()
def control(demo):
    """The demo control HTTP server (``/ctl/raw`` etc.) next to the IMAP port."""
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), build_control_handler(demo.maildir, demo.port)
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _post_raw(url: str, body: bytes) -> dict:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "message/rfc822"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def test_ctl_raw_roundtrip_is_byte_exact(demo, control):
    answer = _post_raw(f"{control}/ctl/raw", RAW)
    assert answer["ok"] and answer["uid"] == 1
    assert answer["sha256"] == RAW_SHA
    assert answer["bytes"] == len(RAW)

    collector = demo.make_collector()
    result = collector.scan()
    assert result.counts["accepted"] == 1
    assert result.counts["marked"] == 1

    row = collector.db.list_messages(10)[0]
    assert row["decision"] == "accepted"
    assert row["raw_sha256"] == RAW_SHA
    # The archived .eml is byte-identical to what was posted.
    assert collector.store.read(row["original_path"]) == RAW
    # The receipt pins the delivered bytes' digest.
    receipt = json.loads(collector.store.read(row["receipt_path"]))
    assert receipt["raw_sha256"] == RAW_SHA
    assert receipt["uid"] == 1 and receipt["uidvalidity"] == 1
    # The folded/base64 MIME still parsed: the CSV report was archived.
    reports = collector.db.list_reports()
    assert [r["report_no"] for r in reports] == ["R900"]
    # Marking \Seen renamed the file but the bytes on the server are intact.
    assert _fetch_raw(demo.port, 1) == RAW


def test_mark_retry_and_restart_do_not_rewrite(demo, tmp_path):
    demo.maildir.deliver(RAW)
    collector = demo.make_collector()

    # STORE succeeds on the server but the reply is lost: the flag was
    # applied by rename only, so the file content is already final.
    demo.maildir.drop_next_store = True
    result = collector.scan()
    assert result.status == "interrupted"
    row = collector.db.list_messages(10)[0]
    assert row["mark_state"] == "pending"
    assert demo.maildir.all_flags()[0]["flags"] == ["\\Seen"]
    assert _fetch_raw(demo.port, 1) == RAW

    # The retry confirms the mark; bytes still untouched.
    assert collector.mark_pending_public() == 1
    assert collector.db.list_messages(10)[0]["mark_state"] == "marked"
    assert _fetch_raw(demo.port, 1) == RAW

    # Source restart: metadata reloads, message files are never rewritten.
    store2 = MailboxStore(tmp_path / "maildir-data")
    server2 = DemoServer(("127.0.0.1", 0), store2)
    threading.Thread(target=server2.serve_forever, daemon=True).start()
    try:
        assert store2.uidvalidity == 1
        assert _fetch_raw(server2.server_address[1], 1) == RAW
        # A fresh collector on the restarted source re-fetches the same bytes
        # and does not duplicate the report.
        collector2 = _make_collector(tmp_path, server2.server_address[1], "inst-b")
        again = collector2.scan()
        assert again.counts["accepted"] == 0
        assert len(collector2.db.list_reports()) == 1
    finally:
        server2.shutdown()
        server2.server_close()


def test_rebuild_uid_reuse_archives_new_bytes(demo):
    demo.maildir.deliver(RAW)
    collector = demo.make_collector()
    collector.scan()
    old = collector.db.list_messages(10)[0]
    assert old["uid"] == 1 and old["uidvalidity"] == 1

    # Rebuild the mailbox (new UIDVALIDITY) and deliver a *different* message
    # that reuses UID 1.
    demo.maildir.rebuild(purge=True)
    csv2 = "报告号,样本号,项目,测值\r\nR901,S002,GLU,5\r\n".encode("utf-8")
    raw2 = RAW.replace(b"R900", b"R901").replace(
        base64.encodebytes(CSV).replace(b"\n", b"\r\n"),
        base64.encodebytes(csv2).replace(b"\n", b"\r\n"),
    )
    assert raw2 != RAW
    raw2_sha = hashlib.sha256(raw2).hexdigest()
    assert demo.maildir.deliver(raw2) == 1  # UID 1 reused in the new generation

    result = collector.scan()
    assert result.uidvalidity == 2
    assert result.counts["accepted"] == 1

    rows = {r["uidvalidity"]: r for r in collector.db.list_messages(10)}
    new = rows[2]
    assert new["uid"] == 1
    assert new["decision"] == "accepted"
    assert new["raw_sha256"] == raw2_sha
    assert collector.store.read(new["original_path"]) == raw2
    # The old generation's record and bytes are untouched.
    assert rows[1]["raw_sha256"] == RAW_SHA
    assert collector.store.read(rows[1]["original_path"]) == RAW
    # Both reports exist; nothing was lost or merged across generations.
    assert {r["report_no"] for r in collector.db.list_reports()} == {"R900", "R901"}
    assert _fetch_raw(demo.port, 1) == raw2

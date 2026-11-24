"""Compare displayed listings and downloads with the final build input files."""

import argparse
import base64
import hashlib
import io
import re
from html.parser import HTMLParser
from pathlib import Path
from zipfile import ZipFile

from make_manual import AUTHOR, BASE, FILES, OUTPUTS, RELEASE


class Manual(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.anchors = set()
        self.downloads = {}
        self.code = []
        self.listing = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            assert attrs["id"] not in self.ids, ("duplicate id", attrs["id"])
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("href", "").startswith("#"):
            self.anchors.add(attrs["href"][1:])
        if tag == "a" and "download" in attrs:
            data = attrs["href"].split("base64,", 1)[1]
            self.downloads[attrs["download"]] = base64.b64decode(data, validate=True)
        if tag == "pre" and attrs.get("class") == "listing":
            self.listing = True
            self.code.append([])

    def handle_endtag(self, tag):
        if tag == "pre":
            self.listing = False

    def handle_data(self, data):
        if self.listing:
            self.code[-1].append(data)


def verify(manual, exe):
    page = manual.read_bytes().decode("utf-8")
    doc = Manual()
    doc.feed(page)
    assert doc.anchors <= doc.ids, doc.anchors - doc.ids
    assert len(doc.code) == len(FILES)
    assert set(doc.downloads) == {*FILES, "USB-Audit-sources.zip"}
    assert hashlib.sha256(exe.read_bytes()).hexdigest() in page
    assert f'<meta name="author" content="{AUTHOR}">' in page and f'USB-Audit {RELEASE}' in page
    assert {"algorithm", "start", "outgoing", "archive-events", "uninstall", "license"} <= doc.ids
    assert page.index('id="algorithm"') < page.index('id="start"')
    assert {"title-setup", "title-collect", "title-transfer", "title-actions"} <= doc.ids
    assert page.count('<svg class="audit-flow"') == 4
    assert {"TransferAudit.ps1", "ArchiveAudit.ps1", "DestinationAudit.ps1"} <= set(FILES)
    license_file = (BASE / "LICENSE").read_bytes()
    license_text = license_file.decode("utf-8")
    assert f"Copyright (c) 2026 {AUTHOR}" in license_text
    assert license_text in page
    with ZipFile(io.BytesIO(doc.downloads["USB-Audit-sources.zip"])) as bundle:
        assert set(bundle.namelist()) == {*FILES, "LICENSE"}
        assert bundle.read("LICENSE") == license_file
        for name, lines in zip(FILES, doc.code):
            folder = "tools" if name == "Uninstall-UsbAudit.ps1" else "src"
            raw = (BASE / folder / name).read_bytes()
            assert bundle.read(name) == raw, ("ZIP content", name)
            assert doc.downloads[name] == raw, ("download bytes", name)
            assert "".join(lines) == raw.decode("utf-8-sig"), ("full displayed listing", name)
            assert hashlib.sha256(raw).hexdigest() in page, ("source digest", name)
            assert re.search(r"(?m)^\s*(?://|#|<!--|/\*)[^\n]*[А-Яа-яЁё]", raw.decode("utf-8-sig")), ("missing Russian comment", name)
    print(f"Manual verified: {len(FILES)} full listings, original bytes and ZIP, EXE SHA-256, four diagrams, release, author and MIT license.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--manual", type=Path, default=BASE / "docs" / "USB-Audit-Guide.html")
    parser.add_argument("--exe", type=Path, default=OUTPUTS / "USB-Audit.exe")
    args = parser.parse_args()
    verify(args.manual, args.exe)

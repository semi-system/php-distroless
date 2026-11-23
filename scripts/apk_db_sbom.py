#!/usr/bin/env python3
"""Chuyển một APK database (lib/apk/db/installed) thành CycloneDX SBOM cho Trivy.

Image distroless dựa trên Baseless có `ID=baseless` trong /etc/os-release nên
`trivy image` không đối chiếu CVE gói OS. SBOM này khai báo các gói không phải
của Baseless (ví dụ gói Wolfi) kèm OS component thật, để `trivy sbom` đọc được.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.parse
import uuid


def parse_db(text: str) -> list[dict[str, str]]:
    packages = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields.setdefault(line[0], line[2:])
        if "P" in fields and "V" in fields:
            packages.append(fields)
    return packages


def build(
    packages: list[dict[str, str]],
    os_name: str,
    os_version: str,
    exclude_prefixes: tuple[str, ...],
) -> dict:
    components = []
    seen: set[tuple[str, str]] = set()
    for package in packages:
        name, version = package["P"], package["V"]
        if name.startswith(exclude_prefixes) or (name, version) in seen:
            continue
        seen.add((name, version))
        arch = package.get("A", "x86_64")
        purl = (
            f"pkg:apk/{os_name}/{name}@{urllib.parse.quote(version)}"
            f"?arch={arch}&distro={os_name}-{os_version}"
        )
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "properties": [
                    {"name": "aquasecurity:trivy:PkgType", "value": os_name},
                    {"name": "aquasecurity:trivy:SrcName", "value": package.get("o", name)},
                    {"name": "aquasecurity:trivy:SrcVersion", "value": version},
                ],
            }
        )
    if not components:
        raise SystemExit("no packages left after filtering; refusing to emit an empty SBOM")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"component": {"type": "container", "name": "apk-inventory", "bom-ref": "root"}},
        "components": [
            {
                "type": "operating-system",
                "bom-ref": f"{os_name}-os",
                "name": os_name,
                "version": os_version,
            },
            *components,
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=pathlib.Path, required=True, help="APK installed database")
    parser.add_argument("--os", dest="os_name", default="wolfi")
    parser.add_argument("--os-version", default="20230201", help="Wolfi uses a fixed VERSION_ID")
    parser.add_argument(
        "--exclude-prefix",
        action="append",
        default=["baseless-"],
        help="skip packages with this prefix (covered by the Baseless OSV gate)",
    )
    parser.add_argument("-o", "--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    document = build(
        parse_db(args.db.read_text(encoding="utf-8")),
        args.os_name,
        args.os_version,
        tuple(args.exclude_prefix),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"{len(document['components']) - 1} packages -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

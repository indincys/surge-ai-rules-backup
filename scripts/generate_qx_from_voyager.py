#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "QuantumultX"
AI_GROUP = "人工智能"
RAW_BASE = "https://raw.githubusercontent.com/indincys/surge-ai-rules-backup/main"

RULE_TYPE_MAP = {
    "DOMAIN": "HOST",
    "HOST": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "HOST-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "HOST-KEYWORD": "HOST-KEYWORD",
    "DOMAIN-WILDCARD": "HOST-WILDCARD",
    "HOST-WILDCARD": "HOST-WILDCARD",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP6-CIDR",
    "IP6-CIDR": "IP6-CIDR",
    "IP-ASN": "IP-ASN",
    "GEOIP": "GEOIP",
    "URL-REGEX": "URL-REGEX",
    "USER-AGENT": "USER-AGENT",
}

UNSUPPORTED_RULE_TYPES = {
    "AND",
    "OR",
    "NOT",
    "PROCESS-NAME",
    "PROTOCOL",
}

KEEP_PARAMS = {"no-resolve"}


@dataclass(frozen=True)
class RemoteRuleSet:
    kind: str
    url: str
    target: str
    source_line: str


def split_csv(line: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    quote_char = ""
    depth = 0
    for char in line:
        if char in {'"', "'"}:
            if not in_quote:
                in_quote = True
                quote_char = char
            elif quote_char == char:
                in_quote = False
            buf.append(char)
            continue
        if not in_quote:
            if char == "(":
                depth += 1
            elif char == ")" and depth:
                depth -= 1
            elif char == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
        buf.append(char)
    parts.append("".join(buf).strip())
    return parts


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def strip_inline_comment(line: str) -> str:
    for match in re.finditer(r"(?<!:)//|#", line):
        idx = match.start()
        if idx > 0 and line[idx - 1] not in {" ", "\t"}:
            continue
        return line[:idx].rstrip()
    return line.rstrip()


def read_sections(path: Path) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(raw)
    return sections


def active_rule_lines(rule_lines: list[str]) -> list[str]:
    result: list[str] = []
    for raw in rule_lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", ";", "//")):
            continue
        result.append(raw)
    return result


def fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": "Codex-QX-Rules/1.0"})
    with urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        return response.read().decode("utf-8", "replace")


def qx_rule_from_parts(rule_type: str, value: str, params: list[str]) -> str | None:
    qx_type = RULE_TYPE_MAP.get(rule_type.upper())
    if not qx_type:
        return None
    cleaned_value = strip_quotes(value)
    if "ruleset.skk.moe" in cleaned_value:
        return None
    kept = [p for p in params if p.strip().lower() in KEEP_PARAMS]
    line = f"{qx_type},{cleaned_value}"
    if kept:
        line += "," + ",".join(kept)
    return line


def qx_domainset_rule(raw: str) -> str | None:
    domain = strip_inline_comment(raw).strip()
    if not domain or domain.startswith(("#", ";", "//")):
        return None
    if "ruleset.skk.moe" in domain:
        return None
    if domain.startswith("*."):
        return f"HOST-WILDCARD,{domain}"
    if domain.startswith("."):
        return f"HOST-SUFFIX,{domain[1:]}"
    if "," in domain:
        return qx_rule_from_external_line(domain, "DOMAIN-SET")
    return f"HOST-SUFFIX,{domain}"


def qx_rule_from_external_line(raw: str, source_kind: str = "RULE-SET") -> str | None:
    stripped = strip_inline_comment(raw).strip()
    if not stripped or stripped.startswith(("#", ";", "//")):
        return None
    if source_kind == "DOMAIN-SET" and "," not in stripped:
        return qx_domainset_rule(stripped)
    parts = split_csv(stripped)
    if len(parts) < 2:
        return None
    rule_type = parts[0].upper()
    if rule_type in UNSUPPORTED_RULE_TYPES:
        return None
    if rule_type not in RULE_TYPE_MAP:
        return None
    tail = parts[2:]
    return qx_rule_from_parts(rule_type, parts[1], tail)


def qx_rule_from_voyager_line(raw: str) -> tuple[str | None, str | None]:
    body = strip_inline_comment(raw.strip())
    parts = split_csv(body)
    if len(parts) < 3:
        return None, raw.strip()
    rule_type = parts[0].upper()
    if rule_type in {"RULE-SET", "DOMAIN-SET"}:
        return None, None
    if rule_type in UNSUPPORTED_RULE_TYPES:
        return None, body
    if rule_type not in RULE_TYPE_MAP:
        return None, body
    return qx_rule_from_parts(rule_type, parts[1], parts[3:]), None


def policyless_source_rule(raw: str) -> str:
    parts = split_csv(strip_inline_comment(raw.strip()))
    if len(parts) < 3:
        return strip_inline_comment(raw.strip())
    return ",".join([parts[0], parts[1], *parts[3:]])


def dedupe(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        result.append(line)
    return result


def write_ruleset(path: Path, title: str, source: str, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [
        f"# NAME: {title}",
        "# FORMAT: Quantumult X filter",
        f"# SOURCE: {source}",
        f"# TOTAL: {len(rules)}",
    ]
    if rules:
        body.extend(["", *rules])
    path.write_text("\n".join(body) + "\n", encoding="utf-8")


def url_file_stem(url: str) -> str:
    parsed = urlsplit(url)
    stem = Path(parsed.path).stem
    return stem or "Ruleset"


def skk_output_path(url: str) -> Path:
    parsed = urlsplit(url)
    parts = [p for p in parsed.path.split("/") if p]
    try:
        idx = parts.index("List")
        category = parts[idx + 1]
        name = Path(parts[idx + 2]).stem
        return OUT_DIR / "SKK" / category / f"{name}.list"
    except (ValueError, IndexError):
        return OUT_DIR / "SKK" / f"{url_file_stem(url)}.list"


def tutu_output_path(url: str) -> Path:
    return OUT_DIR / "TutuBetterRules" / f"{url_file_stem(url)}.list"


def qx_url_for_generated(path: Path) -> str:
    return f"{RAW_BASE}/{path.relative_to(ROOT).as_posix()}"


def blackmatrix_output_path(url: str) -> Path:
    parsed = urlsplit(url)
    parts = [p for p in parsed.path.split("/") if p]
    try:
        idx = parts.index("Surge")
        category = parts[idx + 1]
        name = Path(parts[idx + 2]).name
        return OUT_DIR / "Blackmatrix7" / category / name
    except (ValueError, IndexError):
        return OUT_DIR / "Blackmatrix7" / f"{url_file_stem(url)}.list"


def fetch_convert_write(url: str, kind: str, out_path: Path, title: str) -> tuple[str, int]:
    body = fetch_text(url)
    rules = dedupe(
        [
            rule
            for raw in body.splitlines()
            if (rule := qx_rule_from_external_line(raw, kind)) is not None
        ]
    )
    write_ruleset(out_path, title, url, rules)
    return qx_url_for_generated(out_path), len(rules)


def parse_remote_rulesets(rule_lines: list[str]) -> list[RemoteRuleSet]:
    remotes: list[RemoteRuleSet] = []
    for raw in active_rule_lines(rule_lines):
        body = strip_inline_comment(raw.strip())
        parts = split_csv(body)
        if len(parts) < 3:
            continue
        kind = parts[0].upper()
        if kind not in {"RULE-SET", "DOMAIN-SET"}:
            continue
        url = strip_quotes(parts[1])
        target = strip_quotes(parts[2])
        if url.upper() == "LAN":
            continue
        remotes.append(RemoteRuleSet(kind=kind, url=url, target=target, source_line=body))
    return remotes


def generate_ai_sets(rule_lines: list[str], remotes: list[RemoteRuleSet]) -> dict[str, str]:
    ai_remote_urls = {remote.url for remote in remotes if remote.target == AI_GROUP}
    ai_source_to_generated: dict[str, str] = {}
    remote_rules_by_url: dict[str, list[str]] = {}
    conversion_report: list[str] = []

    for remote in remotes:
        if remote.url not in ai_remote_urls:
            continue
        name = url_file_stem(remote.url)
        out_path = OUT_DIR / f"{name}.list"
        try:
            qx_url, count = fetch_convert_write(remote.url, remote.kind, out_path, name)
            ai_source_to_generated[remote.url] = qx_url
            remote_rules_by_url[remote.url] = [
                rule
                for raw in fetch_text(remote.url).splitlines()
                if (rule := qx_rule_from_external_line(raw, remote.kind)) is not None
            ]
            conversion_report.append(f"- {remote.url} -> {qx_url} ({count} rules)")
        except (OSError, RuntimeError, URLError) as exc:
            conversion_report.append(f"- {remote.url} -> FAILED: {exc}")

    local_rules: list[str] = []
    skipped_local: list[str] = []
    combined: list[str] = []

    for raw in active_rule_lines(rule_lines):
        body = strip_inline_comment(raw.strip())
        parts = split_csv(body)
        if len(parts) < 3:
            continue
        kind = parts[0].upper()
        target = strip_quotes(parts[2])
        if target != AI_GROUP:
            continue
        if kind in {"RULE-SET", "DOMAIN-SET"}:
            combined.extend(remote_rules_by_url.get(strip_quotes(parts[1]), []))
            continue
        converted, skipped = qx_rule_from_voyager_line(raw)
        if converted:
            local_rules.append(converted)
            combined.append(converted)
        elif skipped:
            skipped_local.append(policyless_source_rule(skipped))

    local_rules = dedupe(local_rules)
    combined = dedupe(combined)
    write_ruleset(OUT_DIR / "VoyagerAI.local.list", "VoyagerAI.local", "Voyager.conf local AI rules", local_rules)
    write_ruleset(OUT_DIR / "VoyagerAI.list", "VoyagerAI", "Voyager.conf AI rules and AI remote rulesets", combined)

    report = [
        "# Voyager AI Quantumult X conversion report",
        "",
        "Generated files:",
        f"- {qx_url_for_generated(OUT_DIR / 'VoyagerAI.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'VoyagerAI.local.list')}",
        *conversion_report,
        "",
        "Skipped local AI rules that have no Quantumult X filter equivalent:",
        *(f"- `{line}`" for line in skipped_local),
        "",
    ]
    (OUT_DIR / "VoyagerAI.report.md").write_text("\n".join(report), encoding="utf-8")
    return ai_source_to_generated


def generate_remote_replacements(remotes: list[RemoteRuleSet], ai_replacements: dict[str, str]) -> list[str]:
    replacements: list[str] = []
    generated_seen: set[str] = set()

    for remote in remotes:
        url = remote.url
        replacement: str
        if url in ai_replacements:
            replacement = ai_replacements[url]
        elif "raw.githubusercontent.com/blackmatrix7/ios_rule_script/" in url and "/rule/Surge/" in url:
            out_path = blackmatrix_output_path(url)
            replacement, _ = fetch_convert_write(url, remote.kind, out_path, f"Blackmatrix7 {out_path.stem}")
        elif "ruleset.skk.moe/List/" in url:
            out_path = skk_output_path(url)
            replacement, _ = fetch_convert_write(
                url,
                remote.kind,
                out_path,
                f"SKK {out_path.stem}",
            )
        elif "raw.githubusercontent.com/bunizao/TutuBetterRules/" in url:
            out_path = tutu_output_path(url)
            replacement, _ = fetch_convert_write(
                url,
                remote.kind,
                out_path,
                f"TutuBetterRules {out_path.stem}",
            )
        else:
            out_path = OUT_DIR / "Converted" / f"{url_file_stem(url)}.list"
            replacement, _ = fetch_convert_write(url, remote.kind, out_path, out_path.stem)

        if replacement not in generated_seen:
            replacements.append(replacement)
            generated_seen.add(replacement)

    (OUT_DIR / "VoyagerRemoteRulesets.qx.txt").write_text(
        "\n".join(replacements) + "\n",
        encoding="utf-8",
    )
    return replacements


def write_readme(replacements: list[str]) -> None:
    readme = [
        "# Quantumult X rulesets",
        "",
        "Generated from the local Voyager.conf.",
        "",
        "## AI rulesets",
        "",
        f"- {qx_url_for_generated(OUT_DIR / 'VoyagerAI.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'VoyagerAI.local.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'AIrely.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'GeminiEnhancedV2.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'Claude.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'OpenAI.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'Gemini.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'Copilot.list')}",
        f"- {qx_url_for_generated(OUT_DIR / 'Stripe.list')}",
        "",
        "## Voyager remote ruleset replacements",
        "",
        "One policyless ruleset URL per line:",
        "",
        f"- {qx_url_for_generated(OUT_DIR / 'VoyagerRemoteRulesets.qx.txt')}",
        "",
        "## Notes",
        "",
        "- Generated rulesets are policyless: rule rows do not append strategy or policy-group names.",
        "- PROCESS-NAME and Surge logical rules are not represented in Quantumult X filter resources.",
        "- Source and skip details are in VoyagerAI.report.md.",
        "",
        f"Total remote replacements: {len(replacements)}",
        "",
    ]
    (OUT_DIR / "README.md").write_text("\n".join(readme), encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: generate_qx_from_voyager.py /path/to/Voyager.conf", file=sys.stderr)
        return 2
    source = Path(sys.argv[1]).expanduser().resolve()
    sections = read_sections(source)
    rule_lines = sections.get("Rule", [])
    remotes = parse_remote_rulesets(rule_lines)
    ai_replacements = generate_ai_sets(rule_lines, remotes)
    replacements = generate_remote_replacements(remotes, ai_replacements)
    write_readme(replacements)
    print(f"Generated {len(ai_replacements)} AI remote replacements")
    print(f"Generated {len(replacements)} Voyager remote replacement entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

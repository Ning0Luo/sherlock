"""Small readers for config formats, with no dependencies: a YAML subset
(block and flow maps and lists, quoted and plain scalars, comments) and JSONC
(JSON with // and /* */ comments and trailing commas, as VS Code uses).
Shared by openshell.py and the agentwatch scanner, which inlines this file."""
from __future__ import annotations

import json
import re
from pathlib import Path

# Enough YAML for OpenShell policies and fleet files: block maps and lists,
# flow lists and maps, quoted and plain scalars, comments. PyYAML is used
# when it is installed.

def load_yaml(path: Path):
    text = Path(path).read_text()
    if path.suffix == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        return MiniYaml(text).parse()


class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    out, q = [], None
    for i, c in enumerate(line):
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(c)
    return "".join(out).rstrip()


def _scalar(tok: str):
    t = tok.strip()
    if not t:
        return None
    if t[0] in "'\"" and t[-1] == t[0] and len(t) >= 2:
        return t[1:-1].replace("''", "'") if t[0] == "'" else json.loads(t)
    low = t.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d*", t):
        return float(t)
    return t


def _flow(s: str, i: int = 0):
    """Parse a flow value starting at s[i]; return (value, next index)."""
    while i < len(s) and s[i] == " ":
        i += 1
    if i < len(s) and s[i] in "[{":
        close = "]" if s[i] == "[" else "}"
        is_map = s[i] == "{"
        out = {} if is_map else []
        i += 1
        while True:
            while i < len(s) and s[i] in " ,":
                i += 1
            if i >= len(s):
                raise YamlError("unclosed flow collection")
            if s[i] == close:
                return out, i + 1
            if is_map:
                k, i = _flow_token(s, i, ":")
                i += 1
                v, i = _flow(s, i)
                out[_scalar(k)] = v
            else:
                v, i = _flow(s, i)
                out.append(v)
    tok, i = _flow_token(s, i, ",]}")
    return _scalar(tok), i


def _flow_token(s: str, i: int, stops: str):
    j, q = i, None
    while j < len(s):
        c = s[j]
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c in stops:
            break
        j += 1
    return s[i:j], j


class MiniYaml:
    def __init__(self, text: str):
        self.lines = []
        for raw in text.splitlines():
            if raw.strip().startswith("---") and not self.lines:
                continue
            line = _strip_comment(raw)
            if line.strip():
                if "\t" in line[: len(line) - len(line.lstrip())]:
                    raise YamlError("tabs are not allowed for indentation")
                self.lines.append((len(line) - len(line.lstrip()), line.strip()))
        self.i = 0

    def parse(self):
        if not self.lines:
            return None
        return self.block(self.lines[0][0])

    def block(self, ind: int):
        if self.lines[self.i][1].startswith("- ") or self.lines[self.i][1] == "-":
            return self.seq(ind)
        return self.map(ind)

    def value_after(self, rest: str, ind: int):
        rest = rest.strip()
        if rest in ("|", ">", "|-", ">-"):
            raise YamlError("block scalars are not supported; install PyYAML")
        if rest:
            return _flow(rest)[0] if rest[0] in "[{" else _scalar(rest)
        if self.i < len(self.lines) and self.lines[self.i][0] > ind:
            return self.block(self.lines[self.i][0])
        if self.i < len(self.lines) and self.lines[self.i][0] == ind and self.lines[self.i][1].startswith("-"):
            return self.seq(ind)
        return None

    @staticmethod
    def split_key(text: str):
        """'key: rest' -> (key, rest); None when the line is not a mapping entry."""
        key, j = _flow_token(text, 0, ":")
        if j >= len(text) or (j + 1 < len(text) and text[j + 1] != " "):
            return None
        return key.strip(), text[j + 1:]

    def map(self, ind: int):
        out = {}
        while self.i < len(self.lines) and self.lines[self.i][0] == ind:
            text = self.lines[self.i][1]
            if text.startswith("- ") or text == "-":
                break
            kv = self.split_key(text)
            if kv is None:
                raise YamlError(f"expected 'key: value', got {text!r}")
            self.i += 1
            out[_scalar(kv[0])] = self.value_after(kv[1], ind)
        return out

    def seq(self, ind: int):
        out = []
        while self.i < len(self.lines) and self.lines[self.i][0] == ind:
            text = self.lines[self.i][1]
            if not (text.startswith("- ") or text == "-"):
                break
            item = text[1:].strip()
            if not item:
                self.i += 1
                nested = self.i < len(self.lines) and self.lines[self.i][0] > ind
                out.append(self.block(self.lines[self.i][0]) if nested else None)
            elif item[0] in "[{" or self.split_key(item) is None:
                self.i += 1
                out.append(_flow(item)[0] if item[0] in "[{" else _scalar(item))
            else:
                # "- key: value": a map whose further keys line up with "key"
                sub = ind + len(text) - len(item)
                self.lines[self.i] = (sub, item)
                out.append(self.map(sub))
        return out



def load_jsonc(text: str):
    """Parse JSON that may contain comments and trailing commas."""
    out, i, n, q = [], 0, len(text), False
    while i < n:
        c = text[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                q = False
        elif c == '"':
            q = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned) if cleaned.strip() else {}


def load_config(path: Path):
    """Read a JSON, JSONC or YAML config; {} when missing or unreadable."""
    try:
        text = Path(path).read_text()
    except OSError:
        return {}
    try:
        if Path(path).suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                return yaml.safe_load(text) or {}
            except ImportError:
                return MiniYaml(text).parse() or {}
        return load_jsonc(text)
    except Exception:
        return {}

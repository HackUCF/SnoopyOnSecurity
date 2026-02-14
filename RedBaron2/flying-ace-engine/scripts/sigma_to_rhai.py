#!/usr/bin/env python3
"""Convert Sigma Linux process_creation rules to Rhai YAML rules for flying-ace-engine.

Usage:
    python3 sigma_to_rhai.py [SIGMA_DIR] [OUTPUT_DIR]

Defaults:
    SIGMA_DIR  = /home/noahm/sigma/rules/linux/process_creation
    OUTPUT_DIR = <script_dir>/../rules
"""

import os
import re
import sys
import yaml
from pathlib import Path

SIGMA_DIR = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path("/home/noahm/sigma/rules/linux/process_creation")
)
OUTPUT_DIR = (
    Path(sys.argv[2])
    if len(sys.argv) > 2
    else Path(__file__).resolve().parent.parent / "rules"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def escape_rhai_str(s: str) -> str:
    """Escape a Python string for use inside a Rhai double-quoted string literal.

    Rhai recognises \\, \", \n, \r, \t, \0 as escape sequences.
    Any other back-slash in a Rhai string literal is a compile error,
    so every literal back-slash that is NOT already part of an escape must
    be doubled.
    """
    return s.replace("\\", "\\\\").replace('"', '\\"')


# Rhai has a default max expression depth of 64.  Long OR chains of
# comparisons can exceed this.  We cap the number of OR alternatives to
# keep expressions compilable and leave a comment noting the truncation.
MAX_OR_ALTERNATIVES = 12


def _join_exprs(exprs: list[str], is_all: bool) -> str:
    """Join a list of expressions with AND (is_all) or OR."""
    if len(exprs) == 1:
        return exprs[0]
    joiner = " && " if is_all else " || "
    if not is_all and len(exprs) > MAX_OR_ALTERNATIVES:
        kept = exprs[:MAX_OR_ALTERNATIVES]
        omitted = len(exprs) - MAX_OR_ALTERNATIVES
        return (
            f"({joiner.join(kept)}"
            f" /* truncated: {omitted} more value(s) omitted "
            f"to stay within Rhai complexity limit */)"
        )
    return f"({joiner.join(exprs)})"


# ---------------------------------------------------------------------------
# Convert a single Sigma field|modifier: values  ->  Rhai expression
# ---------------------------------------------------------------------------

def convert_field_condition(field_spec: str, values) -> str:
    parts = field_spec.split("|")
    field = parts[0]
    modifiers = parts[1:]

    # Normalise values to a list of strings
    if not isinstance(values, list):
        values = [values]
    values = [str(v) for v in values]

    is_all = "all" in modifiers
    mods = [m for m in modifiers if m != "all"]
    mod = mods[0] if mods else None

    # ── Image ──────────────────────────────────────────────────────────
    if field == "Image":
        if mod == "endswith":
            exprs = []
            for v in values:
                if v.startswith("/"):
                    # Extract basename: '/bin/uname' -> 'uname', '/base64' -> 'base64'
                    name = v.rsplit("/", 1)[-1]
                    exprs.append(f'e.process_name == "{escape_rhai_str(name)}"')
                else:
                    # e.g. 'awk' should also match gawk, mawk
                    esc = escape_rhai_str(re.escape(v))
                    exprs.append(f're_match(e.process_name, "{esc}$")')
            return _join_exprs(exprs, is_all)

        if mod == "startswith":
            exprs = []
            for v in values:
                esc = escape_rhai_str(re.escape(v))
                exprs.append(f're_match(e.process_executable, "^{esc}")')
            return _join_exprs(exprs, is_all)

        if mod == "contains":
            exprs = [
                f'e.process_executable.contains("{escape_rhai_str(v)}")'
                for v in values
            ]
            return _join_exprs(exprs, is_all)

        if mod == "re":
            exprs = [
                f're_match(e.process_executable, "{escape_rhai_str(v)}")'
                for v in values
            ]
            return _join_exprs(exprs, is_all)

        if mod is None:
            # Exact match on full path
            exprs = [
                f'e.process_executable == "{escape_rhai_str(v)}"'
                for v in values
            ]
            return _join_exprs(exprs, is_all)

    # ── ParentImage ────────────────────────────────────────────────────
    if field == "ParentImage":
        if mod == "endswith":
            exprs = []
            for v in values:
                if v.startswith("/"):
                    # Extract basename: '/rsync' -> 'rsync'
                    name = v.rsplit("/", 1)[-1]
                    exprs.append(
                        f'e.process_pname == "{escape_rhai_str(name)}"'
                    )
                else:
                    esc = escape_rhai_str(re.escape(v))
                    exprs.append(f're_match(e.process_pname, "{esc}$")')
            return _join_exprs(exprs, is_all)

        if mod == "startswith":
            return (
                "false /* ParentImage|startswith: parent executable path "
                "not available, only process_pname accessible */"
            )

        if mod == "contains":
            exprs = [
                f'e.process_pname.contains("{escape_rhai_str(v)}")'
                for v in values
            ]
            return _join_exprs(exprs, is_all)

        if mod is None:
            exprs = [
                f'e.process_pname == "{escape_rhai_str(v)}"'
                for v in values
            ]
            return _join_exprs(exprs, is_all)

    # ── ParentCommandLine (not available) ──────────────────────────────
    if field == "ParentCommandLine":
        return "false /* ParentCommandLine not available in Rhai API */"

    # ── LogonId (not available) ────────────────────────────────────────
    if field == "LogonId":
        return "false /* LogonId not available in Rhai API */"

    # ── CommandLine ────────────────────────────────────────────────────
    if field == "CommandLine":
        rf = "e.process_args"
        if mod == "contains":
            exprs = [f'{rf}.contains("{escape_rhai_str(v)}")' for v in values]
            return _join_exprs(exprs, is_all)
        if mod == "startswith":
            exprs = [
                f'{rf}.starts_with("{escape_rhai_str(v)}")' for v in values
            ]
            return _join_exprs(exprs, is_all)
        if mod == "endswith":
            exprs = [
                f'{rf}.ends_with("{escape_rhai_str(v)}")' for v in values
            ]
            return _join_exprs(exprs, is_all)
        if mod == "re":
            exprs = [
                f're_match({rf}, "{escape_rhai_str(v)}")' for v in values
            ]
            return _join_exprs(exprs, is_all)
        if mod is None:
            exprs = [f'{rf} == "{escape_rhai_str(v)}"' for v in values]
            return _join_exprs(exprs, is_all)

    # ── User ───────────────────────────────────────────────────────────
    if field == "User":
        rf = "e.user_name"
        if mod == "contains":
            exprs = [f'{rf}.contains("{escape_rhai_str(v)}")' for v in values]
            return _join_exprs(exprs, is_all)
        if mod is None:
            exprs = [f'{rf} == "{escape_rhai_str(v)}"' for v in values]
            return _join_exprs(exprs, is_all)

    # ── CurrentDirectory ───────────────────────────────────────────────
    if field == "CurrentDirectory":
        rf = "e.process_working_directory"
        if mod == "contains":
            exprs = [f'{rf}.contains("{escape_rhai_str(v)}")' for v in values]
            return _join_exprs(exprs, is_all)
        if mod is None:
            exprs = [f'{rf} == "{escape_rhai_str(v)}"' for v in values]
            return _join_exprs(exprs, is_all)

    # ── Fallback ───────────────────────────────────────────────────────
    return f"true /* unsupported: {field_spec} */"


# ---------------------------------------------------------------------------
# Convert a Sigma selection dict  ->  Rhai expression  (fields are ANDed)
# ---------------------------------------------------------------------------

def convert_selection(sel_dict: dict) -> str:
    conditions = []
    for field_spec, values in sel_dict.items():
        conditions.append(convert_field_condition(field_spec, values))
    if not conditions:
        return "true"
    if len(conditions) == 1:
        return conditions[0]
    return " && ".join(conditions)


# ---------------------------------------------------------------------------
# Condition tokeniser
# ---------------------------------------------------------------------------

class _Tok:
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    ONE_OF = "ONE_OF"
    ALL_OF = "ALL_OF"
    IDENT = "IDENT"
    EOF = "EOF"

    def __init__(self, ty: str, val: str = ""):
        self.ty = ty
        self.val = val

    def __repr__(self):
        return f"Tok({self.ty}, {self.val!r})"


def _tokenise(cond: str) -> list[_Tok]:
    tokens: list[_Tok] = []
    i = 0
    s = cond.strip()
    while i < len(s):
        if s[i].isspace():
            i += 1
            continue
        if s[i] == "(":
            tokens.append(_Tok(_Tok.LPAREN, "("))
            i += 1
            continue
        if s[i] == ")":
            tokens.append(_Tok(_Tok.RPAREN, ")"))
            i += 1
            continue
        rest = s[i:]
        # "1 of"
        m = re.match(r"1\s+of\s+", rest)
        if m:
            tokens.append(_Tok(_Tok.ONE_OF))
            i += m.end()
            continue
        # "all of"
        m = re.match(r"all\s+of\s+", rest)
        if m:
            tokens.append(_Tok(_Tok.ALL_OF))
            i += m.end()
            continue
        # keywords (boundary-aware)
        m = re.match(r"and(?![a-zA-Z0-9_])", rest)
        if m:
            tokens.append(_Tok(_Tok.AND))
            i += m.end()
            continue
        m = re.match(r"or(?![a-zA-Z0-9_])", rest)
        if m:
            tokens.append(_Tok(_Tok.OR))
            i += m.end()
            continue
        m = re.match(r"not(?![a-zA-Z0-9_])", rest)
        if m:
            tokens.append(_Tok(_Tok.NOT))
            i += m.end()
            continue
        # identifier (may end with * for glob)
        m = re.match(r"[a-zA-Z_][a-zA-Z0-9_]*\*?", rest)
        if m:
            tokens.append(_Tok(_Tok.IDENT, m.group()))
            i += m.end()
            continue
        # skip unknown char
        i += 1
    tokens.append(_Tok(_Tok.EOF))
    return tokens


# ---------------------------------------------------------------------------
# Condition parser  (recursive-descent)
# ---------------------------------------------------------------------------

def _glob_match(name: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


class _CondParser:
    def __init__(self, tokens: list[_Tok], selections: dict[str, str]):
        self.tokens = tokens
        self.pos = 0
        self.sels = selections

    def _peek(self) -> _Tok:
        return self.tokens[self.pos]

    def _advance(self) -> _Tok:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def _expect(self, ty: str) -> _Tok:
        t = self._advance()
        if t.ty != ty:
            raise ValueError(f"expected {ty}, got {t}")
        return t

    # ── grammar ──

    def parse(self) -> str:
        return self._or_expr()

    def _or_expr(self) -> str:
        left = self._and_expr()
        while self._peek().ty == _Tok.OR:
            self._advance()
            right = self._and_expr()
            left = f"({left}) || ({right})"
        return left

    def _and_expr(self) -> str:
        left = self._not_expr()
        while self._peek().ty == _Tok.AND:
            self._advance()
            right = self._not_expr()
            left = f"({left}) && ({right})"
        return left

    def _not_expr(self) -> str:
        if self._peek().ty == _Tok.NOT:
            self._advance()
            inner = self._not_expr()
            return f"!({inner})"
        return self._primary()

    def _primary(self) -> str:
        tok = self._peek()

        if tok.ty == _Tok.LPAREN:
            self._advance()
            expr = self._or_expr()
            self._expect(_Tok.RPAREN)
            return f"({expr})"

        if tok.ty == _Tok.ONE_OF:
            self._advance()
            pat = self._expect(_Tok.IDENT).val
            matching = [n for n in self.sels if _glob_match(n, pat)]
            if not matching:
                return f"false /* no selections match: {pat} */"
            parts = [f"({self.sels[n]})" for n in matching]
            if len(parts) == 1:
                return parts[0]
            if len(parts) > MAX_OR_ALTERNATIVES:
                kept = parts[:MAX_OR_ALTERNATIVES]
                omitted = len(parts) - MAX_OR_ALTERNATIVES
                return (
                    " || ".join(kept)
                    + f" /* truncated: {omitted} more selection(s) omitted"
                    f" to stay within Rhai complexity limit */"
                )
            return " || ".join(parts)

        if tok.ty == _Tok.ALL_OF:
            self._advance()
            pat = self._expect(_Tok.IDENT).val
            matching = [n for n in self.sels if _glob_match(n, pat)]
            if not matching:
                return f"true /* no selections match: {pat} */"
            parts = [f"({self.sels[n]})" for n in matching]
            if len(parts) == 1:
                return parts[0]
            return " && ".join(parts)

        if tok.ty == _Tok.IDENT:
            self._advance()
            name = tok.val
            if name in self.sels:
                return self.sels[name]
            return f"false /* unknown selection: {name} */"

        raise ValueError(f"unexpected token: {tok}")


# ---------------------------------------------------------------------------
# Top-level: convert one Sigma file  ->  Rhai rule dict
# ---------------------------------------------------------------------------

def convert_sigma_file(path: Path) -> dict | None:
    with open(path) as fh:
        rule = yaml.safe_load(fh)

    if not rule or "detection" not in rule:
        return None

    detection = rule["detection"]
    condition_str = detection.get("condition", "selection")

    # Build per-selection Rhai expressions
    selections: dict[str, str] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            selections[key] = convert_selection(value)
        elif isinstance(value, list):
            # List of alternative sub-selections (OR)
            sub = []
            for item in value:
                if isinstance(item, dict):
                    sub.append(convert_selection(item))
                else:
                    sub.append("true /* unexpected list element */")
            if len(sub) == 1:
                selections[key] = sub[0]
            else:
                selections[key] = "(" + " || ".join(sub) + ")"

    # Parse the condition string into a Rhai boolean expression
    tokens = _tokenise(condition_str)
    parser = _CondParser(tokens, selections)
    eval_expr = parser.parse()

    # Rule name: strip proc_creation_lnx_ prefix, add sigma_ prefix
    stem = path.stem  # e.g. proc_creation_lnx_base64_decode
    name = stem.replace("proc_creation_lnx_", "sigma_", 1)

    return {"name": name, "mode": "alert", "eval": eval_expr}


# ---------------------------------------------------------------------------
# Write a Rhai rule dict to YAML
# ---------------------------------------------------------------------------

def write_rhai_rule(rule: dict, out_path: Path):
    with open(out_path, "w") as fh:
        fh.write(f"name: {rule['name']}\n")
        fh.write(f"mode: {rule['mode']}\n")
        fh.write("eval: |\n")
        fh.write("  (\n")
        fh.write(f"    {rule['eval']}\n")
        fh.write("  )\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    sigma_files = sorted(SIGMA_DIR.glob("*.yml"))
    print(f"Found {len(sigma_files)} Sigma rules in {SIGMA_DIR}")
    print(f"Output directory: {OUTPUT_DIR}\n")

    ok = 0
    fail = 0

    for sf in sigma_files:
        try:
            rule = convert_sigma_file(sf)
            if rule is None:
                print(f"  SKIP  {sf.name}  (no detection block)")
                continue

            out = OUTPUT_DIR / f"{rule['name']}.yaml"
            write_rhai_rule(rule, out)
            ok += 1
            print(f"  OK    {sf.name}  ->  {out.name}")
        except Exception as exc:
            fail += 1
            print(f"  FAIL  {sf.name}:  {exc}")

    print(f"\nDone: {ok} converted, {fail} failed, {len(sigma_files)} total")


if __name__ == "__main__":
    main()

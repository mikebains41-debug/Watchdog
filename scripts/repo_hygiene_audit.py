#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
scripts/repo_hygiene_audit.py -- AST-based code-hygiene auditor
*** WATCHDOG ***

Two tools from SECURITY_REVIEW_2026-09-04 and the dead-import work, done
properly with Python's `ast` module instead of regex:

1. BARE-EXCEPT SWEEP (review M-finding: 461 bare `except:` clauses).
   A bare `except:` in a DETECTOR means "if the detector breaks, it reports
   clean" -- silent false negatives, the worst failure mode for security
   code. In REMEDIATION code it means a failed privileged action reports
   success. This tool finds every bare `except:` and every `except Exception:`
   that swallows silently (no `as e`, or a body that is just `pass`), ranks
   them by the risk of the file they live in (detection/ and remediation/
   first), and can optionally rewrite the PURE `except:` -> `except Exception:`
   form (a safe, semantics-preserving narrowing that stops catching
   SystemExit/KeyboardInterrupt). It NEVER changes what the handler does --
   deciding what a handler should do is a human job, file by file.

2. AST DEAD-CODE AUDIT (replaces the regex audit_dead_imports.py).
   Resolves whether a module's public names are ever USED anywhere in the
   repo: called, instantiated, subclassed (class X(Base)), used as a
   decorator, or referenced as an attribute. The regex version missed
   inheritance and would have recommended deleting threat_intel.py, a live
   base class. AST does not have that blind spot.

Report-only by default. --fix-bare-except is opt-in and only performs the
safe narrowing. Deletes nothing, ever.

Run from repo root:
  python3 scripts/repo_hygiene_audit.py                 # report
  python3 scripts/repo_hygiene_audit.py --fix-bare-except  # safe narrowing
  python3 scripts/repo_hygiene_audit.py --dead alerting/foo.py intelligence/bar.py
"""
import argparse
import ast
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RISK_ORDER = ["detection", "remediation", "intelligence", "runtime", "alerting",
              "orchestration", "api", "saas", "forensics", "telemetry", "todo", "scripts", "tests"]
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def py_files():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def risk_rank(path):
    rel = os.path.relpath(path, REPO)
    top = rel.split(os.sep)[0]
    return RISK_ORDER.index(top) if top in RISK_ORDER else len(RISK_ORDER)


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _parse(path):
    try:
        return ast.parse(_read(path), filename=path)
    except SyntaxError as e:
        return e


# ---------------------------------------------------------------------------
# 1 -- bare-except sweep
# ---------------------------------------------------------------------------
def _handler_is_silent(h: ast.ExceptHandler) -> bool:
    body = h.body
    if len(body) == 1 and isinstance(body[0], ast.Pass):
        return True
    if len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        return True   # bare docstring/constant as the only statement
    return False


def sweep_bare_except(fix=False):
    findings = []
    for path in sorted(py_files(), key=risk_rank):
        tree = _parse(path)
        if isinstance(tree, SyntaxError):
            findings.append({"file": os.path.relpath(path, REPO), "line": tree.lineno,
                             "kind": "SYNTAX_ERROR", "detail": str(tree.msg)})
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            rel = os.path.relpath(path, REPO)
            if node.type is None:
                findings.append({"file": rel, "line": node.lineno, "kind": "BARE_EXCEPT",
                                 "silent": _handler_is_silent(node),
                                 "detail": "catches SystemExit/KeyboardInterrupt too; hides all failures"})
            elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException") \
                    and node.name is None and _handler_is_silent(node):
                findings.append({"file": rel, "line": node.lineno, "kind": "SILENT_EXCEPTION",
                                 "silent": True,
                                 "detail": f"except {node.type.id}: pass -- error swallowed, no `as e`, nothing logged"})
    if fix:
        _apply_safe_narrowing(findings)
    return findings


def _apply_safe_narrowing(findings):
    """Rewrite ONLY the token `except:` -> `except Exception:` on flagged lines.
    Semantics-preserving except that SystemExit/KeyboardInterrupt now propagate
    (which is what you want). Handler bodies are untouched."""
    by_file = {}
    for f in findings:
        if f["kind"] == "BARE_EXCEPT":
            by_file.setdefault(f["file"], []).append(f["line"])
    for rel, lines in by_file.items():
        path = os.path.join(REPO, rel)
        src = _read(path).split("\n")
        changed = 0
        for ln in lines:
            i = ln - 1
            if 0 <= i < len(src) and src[i].lstrip().startswith("except:"):
                src[i] = src[i].replace("except:", "except Exception:", 1)
                changed += 1
        if changed:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(src))
            print(f"  fixed {changed} bare except -> except Exception in {rel}")


# ---------------------------------------------------------------------------
# 2 -- AST dead-code audit
# ---------------------------------------------------------------------------
def _module_name(path):
    rel = os.path.relpath(path, REPO)[:-3]
    return rel.replace(os.sep, ".")


def _public_defs(tree):
    return [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and not n.name.startswith("_")]


class _UseFinder(ast.NodeVisitor):
    """Records how each target name is used in a file."""

    def __init__(self, names):
        self.names = set(names)
        self.uses = {}   # name -> set(kinds)

    def _hit(self, name, kind):
        if name in self.names:
            self.uses.setdefault(name, set()).add(kind)

    def visit_Call(self, node):
        f = node.func
        if isinstance(f, ast.Name):
            self._hit(f.id, "call")
        elif isinstance(f, ast.Attribute):
            self._hit(f.attr, "call")
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        for b in node.bases:
            if isinstance(b, ast.Name):
                self._hit(b.id, "inherit")
            elif isinstance(b, ast.Attribute):
                self._hit(b.attr, "inherit")
        for d in node.decorator_list:
            if isinstance(d, ast.Name):
                self._hit(d.id, "decorator")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for d in node.decorator_list:
            if isinstance(d, ast.Name):
                self._hit(d.id, "decorator")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        self._hit(node.attr, "attribute")
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self._hit(node.id, "reference")
        self.generic_visit(node)


def audit_dead(target_rel_paths):
    results = []
    all_trees = {}
    for p in py_files():
        t = _parse(p)
        if not isinstance(t, SyntaxError):
            all_trees[p] = t
    for rel in target_rel_paths:
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path):
            results.append({"file": rel, "state": "MISSING"})
            continue
        tree = all_trees.get(path)
        if tree is None:
            results.append({"file": rel, "state": "UNPARSEABLE"})
            continue
        defs = _public_defs(tree)
        modname = _module_name(path)
        importers, uses = [], {}
        for p, t in all_trees.items():
            if p == path:
                continue
            imported = any(
                (isinstance(n, ast.ImportFrom) and n.module and (n.module == modname or n.module.endswith(modname.split(".")[-1])))
                or (isinstance(n, ast.Import) and any(a.name.endswith(modname.split(".")[-1]) for a in n.names))
                for n in ast.walk(t))
            if imported:
                importers.append(os.path.relpath(p, REPO))
            uf = _UseFinder(defs)
            uf.visit(t)
            for name, kinds in uf.uses.items():
                # a bare 'reference' in the importing file's own import line is not a use
                real = kinds - {"reference"} if os.path.relpath(p, REPO) in importers and kinds == {"reference"} else kinds
                if real:
                    uses.setdefault(name, []).append((os.path.relpath(p, REPO), sorted(real)))
        if uses:
            state = "LIVE"
        elif importers:
            state = "DEAD_IMPORT"
        else:
            state = "ORPHAN"
        results.append({"file": rel, "defines": defs, "imported_by": importers,
                        "used": uses, "state": state})
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="Watchdog AST hygiene audit (report-only unless --fix-bare-except)")
    ap.add_argument("--fix-bare-except", action="store_true",
                    help="rewrite bare `except:` -> `except Exception:` (safe narrowing only)")
    ap.add_argument("--dead", nargs="*", default=None, help="repo-relative .py files to dead-code audit")
    ap.add_argument("--top", type=int, default=40, help="max bare-except findings to print")
    a = ap.parse_args(argv)

    print("=" * 66)
    print("WATCHDOG REPO HYGIENE AUDIT (AST)")
    print("=" * 66)
    f = sweep_bare_except(fix=a.fix_bare_except)
    bare = [x for x in f if x["kind"] == "BARE_EXCEPT"]
    silent = [x for x in f if x["kind"] == "SILENT_EXCEPTION"]
    syn = [x for x in f if x["kind"] == "SYNTAX_ERROR"]
    print(f"\n## bare except: {len(bare)}   silent `except Exception: pass`: {len(silent)}   syntax errors: {len(syn)}")
    by_dir = {}
    for x in bare + silent:
        by_dir[x["file"].split(os.sep)[0]] = by_dir.get(x["file"].split(os.sep)[0], 0) + 1
    print("   by top-level dir (highest risk first):", dict(sorted(by_dir.items(), key=lambda kv: risk_rank(os.path.join(REPO, kv[0])))))
    for x in (bare + silent)[: a.top]:
        print(f"   {x['file']}:{x['line']}  {x['kind']}{'  [SILENT]' if x.get('silent') else ''}")
    if len(bare + silent) > a.top:
        print(f"   ... {len(bare + silent) - a.top} more")
    if a.fix_bare_except:
        print("\n   NOTE: only `except:` -> `except Exception:` was rewritten. Handler bodies unchanged.")
        print("   Silent `pass` handlers still need a human to decide what they should do.")

    if a.dead is not None:
        targets = a.dead or ["intelligence/threat_intel.py"]
        print("\n## dead-code audit (AST; call / inherit / decorator / attribute aware)")
        for r in audit_dead(targets):
            print(f"\n   {r['file']}: {r['state']}")
            if r.get("defines") is not None:
                print(f"     defines     : {r['defines']}")
                print(f"     imported by : {r['imported_by'] or 'nothing'}")
                print(f"     used        : {r['used'] or 'nothing'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

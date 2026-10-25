"""Trusted static frontend. Input is source data; target code is never executed."""

from __future__ import annotations

import ast
import json
import sys
from typing import Any

MAX_SOURCE = 8 << 20
MAX_NODES = 100000
MAX_VALUES = 200000
MAX_DEPTH = 32
UNKNOWN = {"kind": "unknown"}


class LimitError(Exception):
    pass


class Scope:
    def __init__(self, parent: Scope | None, kind: str) -> None:
        self.parent = parent
        self.kind = kind
        self.bindings: dict[str, list[Any]] = {}
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        self.wildcard = False

    def bind(self, name: str, value: Any) -> None:
        self.bindings.setdefault(name, []).append(value)


def lexical_parent(scope: Scope) -> Scope:
    while scope.kind == "class" and scope.parent is not None:
        scope = scope.parent
    return scope


class Index(ast.NodeVisitor):
    def __init__(self) -> None:
        self.root = Scope(None, "module")
        self.scope = self.root
        self.scopes = [self.root]
        self.calls: list[tuple[ast.Call, Scope]] = []
        self.settings: list[tuple[ast.Attribute, ast.expr | None, Scope]] = []
        self.writes: list[tuple[ast.Attribute, Scope]] = []
        self.mutations: set[str] = set()
        self.attribute_writes: set[tuple[int, str, str]] = set()
        self.issues: list[dict[str, Any]] = []
        self.nodes = 0
        self.values = 0
        self.limited = False

    def visit(self, node: ast.AST) -> Any:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise LimitError("AST node limit exceeded")
        return super().visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            name = item.asname or item.name.split(".")[0]
            symbol = item.name if item.asname else name
            self.scope.bind(name, {"kind": "symbol", "text": symbol, "line": node.lineno})

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        prefix = node.module or ""
        if node.level:
            prefix = "local:" + prefix
        for item in node.names:
            if item.name == "*":
                self.scope.wildcard = True
                self.issues.append({"line": node.lineno, "message": "wildcard import limits symbol resolution"})
            else:
                self.scope.bind(item.asname or item.name, {"kind": "symbol", "text": prefix + "." + item.name, "line": node.lineno})

    def visit_Global(self, node: ast.Global) -> None:
        self.scope.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.scope.nonlocals.update(node.names)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.scope.bind(node.id, None)

    def target(self, target: ast.expr, value: ast.expr | None) -> None:
        if isinstance(target, ast.Name):
            self.scope.bind(target.id, value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.target(item, None)
        elif isinstance(target, ast.Starred):
            self.target(target.value, None)
        elif isinstance(target, ast.Attribute):
            self.writes.append((target, self.scope))
            self.settings.append((target, value, self.scope))
            self.visit(target.value)
        elif isinstance(target, ast.Subscript):
            if isinstance(target.value, ast.Name):
                self.scope.bind(target.value.id, None)
            elif isinstance(target.value, ast.Attribute) and target.value.attr == "__dict__":
                self.writes.append((target.value, self.scope))
            self.visit(target.value)
            self.visit(target.slice)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self.target(target, node.value if len(node.targets) == 1 else None)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.target(node.target, node.value)
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.target(node.target, None)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        previous = self.scope
        while self.scope.kind == "comprehension" and self.scope.parent is not None:
            self.scope = self.scope.parent
        self.target(node.target, node.value if self.scope is previous else None)
        self.scope = previous
        self.visit(node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self.target(target, None)

    def function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        previous = self.scope
        if not isinstance(node, ast.Lambda):
            previous.bind(node.name, None)
            for decorator in node.decorator_list:
                self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        self.scope = Scope(lexical_parent(previous), "function")
        self.scopes.append(self.scope)
        for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            self.scope.bind(argument.arg, None)
        for argument in [node.args.vararg, node.args.kwarg]:
            if argument is not None:
                self.scope.bind(argument.arg, None)
        if isinstance(node, ast.Lambda):
            self.visit(node.body)
        else:
            for statement in node.body:
                self.visit(statement)
        self.scope = previous

    visit_FunctionDef = function
    visit_AsyncFunctionDef = function
    visit_Lambda = function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        previous = self.scope
        previous.bind(node.name, None)
        for expression in [*node.bases, *node.decorator_list, *(item.value for item in node.keywords)]:
            self.visit(expression)
        self.scope = Scope(lexical_parent(previous), "class")
        self.scopes.append(self.scope)
        for statement in node.body:
            self.visit(statement)
        self.scope = previous

    def comprehension(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        previous = self.scope
        self.visit(node.generators[0].iter)
        self.scope = Scope(lexical_parent(previous), "comprehension")
        self.scopes.append(self.scope)
        for index, generator in enumerate(node.generators):
            self.target(generator.target, None)
            if index:
                self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.scope = previous

    visit_ListComp = comprehension
    visit_SetComp = comprehension
    visit_DictComp = comprehension
    visit_GeneratorExp = comprehension

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.scope.bind(node.name, None)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.scope.bind(node.name, None)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.scope.bind(node.name, None)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.scope.bind(node.rest, None)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((node, self.scope))
        self.generic_visit(node)

    def owner(self, scope: Scope, name: str) -> Scope | None:
        if name in scope.globals:
            return self.root
        current = scope.parent if name in scope.nonlocals else scope
        while current is not None:
            if current.wildcard:
                return None
            if name in current.bindings:
                return current
            current = current.parent
        return None

    def origin(self, expression: ast.expr, scope: Scope, seen: set[tuple[int, str]] | None = None) -> tuple[int, str] | None:
        if not isinstance(expression, ast.Name):
            return None
        owner = self.owner(scope, expression.id)
        if owner is None:
            return None
        key = (id(owner), expression.id)
        seen = set() if seen is None else seen
        if key in seen:
            return None
        seen.add(key)
        bindings = owner.bindings.get(expression.id, [])
        if not bindings:
            return None
        if len(bindings) == 1 and isinstance(bindings[0], ast.Name):
            return self.origin(bindings[0], owner, seen)
        return key

    def finalize(self) -> None:
        for scope in self.scopes:
            for name in scope.globals | scope.nonlocals:
                if name not in scope.bindings:
                    continue
                owner = self.root if name in scope.globals else self.owner(scope, name)
                if owner is not None and owner is not scope:
                    owner.bind(name, None)
        for node, scope in self.calls:
            function = qualified(self.resolve(node.func, scope, set(), 0, False))
            if function not in {"builtins.setattr", "builtins.delattr"} or len(node.args) < 2:
                continue
            base = self.resolve(node.args[0], scope, set(), 0, False)
            attribute = self.resolve(node.args[1], scope, set(), 0, False)
            name = attribute.get("text") if attribute.get("kind") == "string" else None
            namespace = qualified(base)
            if namespace:
                self.mutations.add(namespace + "." + name if name else namespace)
            origin = self.origin(node.args[0], scope)
            if origin is not None:
                self.attribute_writes.add((*origin, name or "*"))
        for target, scope in self.writes:
            base = self.resolve(target.value, scope, set(), 0, False)
            name = qualified(base)
            if name:
                self.mutations.add(name if target.attr in {"__dict__", "__class__"} else name + "." + target.attr)
            origin = self.origin(target.value, scope)
            if origin is not None:
                self.attribute_writes.add((*origin, target.attr))
        self.values = 0

    def resolve(self, node: ast.expr | None, scope: Scope, seen: set[tuple[int, str]], depth: int = 0, mutations: bool = True) -> dict[str, Any]:
        self.values += 1
        if node is None:
            return UNKNOWN
        if depth > MAX_DEPTH or self.values > MAX_VALUES:
            self.limited = True
            return UNKNOWN
        if isinstance(node, ast.Name):
            owner = self.owner(scope, node.id)
            if owner is None:
                if node.id in {"bytes", "bytearray", "len", "setattr", "delattr"} and not any(s.wildcard for s in self.scopes):
                    return {"kind": "symbol", "text": "builtins." + node.id}
                return UNKNOWN
            bindings = owner.bindings.get(node.id, [])
            key = (id(owner), node.id)
            if len(bindings) != 1 or key in seen:
                return UNKNOWN
            value = bindings[0]
            if isinstance(value, dict):
                if owner is scope and value.get("line", 0) > node.lineno:
                    return UNKNOWN
                return {"kind": value["kind"], "text": value["text"]}
            if owner is scope and getattr(value, "lineno", 0) > node.lineno:
                return UNKNOWN
            return self.resolve(value, owner, seen | {key}, depth + 1, mutations)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value, scope, seen, depth + 1, mutations)
            origin = self.origin(node.value, scope)
            if mutations and origin is not None and (
                (*origin, node.attr) in self.attribute_writes or (*origin, "*") in self.attribute_writes
            ):
                return {"kind": "unknown", "hint": qualified(base), "base": base}
            return {"kind": "attribute", "text": node.attr, "base": base}
        if isinstance(node, ast.Constant):
            if node.value is None:
                return {"kind": "none"}
            if isinstance(node.value, bytes):
                return {"kind": "bytes", "length": len(node.value)}
            if isinstance(node.value, bool):
                return {"kind": "bool", "text": str(node.value).lower()}
            if isinstance(node.value, int) and node.value.bit_length() <= 63:
                return {"kind": "int", "integer": node.value}
            if isinstance(node.value, str):
                if len(node.value) <= 512:
                    return {"kind": "string", "text": node.value, "length": len(node.value)}
                return {"kind": "string", "length": len(node.value)}
            return UNKNOWN
        if isinstance(node, ast.Call):
            if len(node.args) + len(node.keywords) > 64:
                self.limited = True
                return UNKNOWN
            return {"kind": "call", "base": self.resolve(node.func, scope, seen, depth + 1, mutations),
                    "args": [self.resolve(arg, scope, seen, depth + 1, mutations) for arg in node.args],
                    "keywords": {item.arg or "**": self.resolve(item.value, scope, seen, depth + 1, mutations) for item in node.keywords}}
        if isinstance(node, ast.Starred):
            return {"kind": "unpack"}
        if isinstance(node, ast.BinOp):
            return {"kind": "binary", "text": type(node.op).__name__,
                    "args": [self.resolve(node.left, scope, seen, depth + 1, mutations),
                             self.resolve(node.right, scope, seen, depth + 1, mutations)]}
        if isinstance(node, ast.UnaryOp):
            return {"kind": "unary", "text": type(node.op).__name__,
                    "args": [self.resolve(node.operand, scope, seen, depth + 1, mutations)]}
        if isinstance(node, (ast.Tuple, ast.List)) and len(node.elts) <= 64:
            return {"kind": "sequence", "args": [self.resolve(item, scope, seen, depth + 1, mutations) for item in node.elts]}
        return UNKNOWN


def qualified(value: dict[str, Any]) -> str:
    if value.get("kind") == "symbol":
        return value.get("text", "")
    if value.get("kind") == "attribute":
        base = qualified(value["base"])
        return base + "." + value["text"] if base else ""
    return ""


def analyze(source: bytes) -> dict[str, Any]:
    tree = ast.parse(source, filename="<ciphertrail>", mode="exec")
    for count, _ in enumerate(ast.walk(tree), 1):
        if count > MAX_NODES:
            raise LimitError("AST node limit exceeded")
    index = Index()
    index.visit(tree)
    index.finalize()
    calls = []
    for node, scope in index.calls:
        calls.append({"line": node.lineno, "column": node.col_offset,
                      "value": index.resolve(node, scope, set())})
    settings = []
    for target, value, scope in index.settings:
        settings.append({"line": target.lineno, "attribute": target.attr,
                         "receiver": index.resolve(target.value, scope, set()),
                         "value": index.resolve(value, scope, set())})
    if index.limited:
        index.issues.append({"line": 0, "message": "bounded expression-resolution limit reached"})
    return {"calls": calls, "settings": settings, "mutations": sorted(index.mutations), "issues": index.issues}


def main() -> None:
    result: dict[str, Any] = {"protocol": 1, "version": ".".join(map(str, sys.version_info[:3]))}
    if sys.version_info < (3, 10):
        result["error"] = {"kind": "runtime", "line": 0}
    else:
        source = sys.stdin.buffer.read(MAX_SOURCE + 1)
        try:
            if len(source) > MAX_SOURCE:
                raise LimitError("source byte limit exceeded")
            result.update(analyze(source))
        except SyntaxError as error:
            result["error"] = {"kind": "syntax", "line": error.lineno or 0}
        except (LimitError, RecursionError, MemoryError):
            result["error"] = {"kind": "limit", "line": 0}
        except ValueError:
            result["error"] = {"kind": "syntax", "line": 0}
    json.dump(result, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()

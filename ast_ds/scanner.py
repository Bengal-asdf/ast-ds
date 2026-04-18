import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import Config

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


@dataclass
class Endpoint:
    method: str
    path: str
    function_name: str
    source_file: Path
    lineno: int
    args: list[str] = field(default_factory=list)
    source_code: Optional[str] = None


def scan(config: Config) -> list[Endpoint]:
    files = _collect_files(config)
    endpoints = []

    for file in files:
        endpoints.extend(_scan_file(file))

    return endpoints


def _collect_files(config: Config) -> list[Path]:
    if config.is_dir:
        return sorted(config.target.rglob("*.py"))
    else:
        return [config.target]


def _scan_file(file: Path) -> list[Endpoint]:
    try:
        source = file.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return []

    endpoints = []
    lines = source.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        for decorator in node.decorator_list:
            method, route_path = _extract_route(decorator)
            if method is None:
                continue

            args = _extract_args(node)
            func_source = _extract_function_source(lines, node)

            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=route_path,
                    function_name=node.name,
                    source_file=file,
                    lineno=node.lineno,
                    args=args,
                    source_code=func_source,
                )
            )

    return endpoints


def _extract_route(decorator: ast.expr) -> tuple[Optional[str], str]:
    # @router.post("/path") or @app.get("/path")
    if not isinstance(decorator, ast.Call):
        return None, ""

    func = decorator.func

    if not isinstance(func, ast.Attribute):
        return None, ""

    method = func.attr.lower()
    if method not in HTTP_METHODS:
        return None, ""

    # Extraer el path del primer argumento
    if not decorator.args:
        return method, "/"

    first_arg = decorator.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return method, first_arg.value

    return method, "/"


def _extract_args(func_node: ast.FunctionDef) -> list[str]:
    args = []
    for arg in func_node.args.args:
        if arg.arg not in ("self", "request", "response", "db", "session"):
            args.append(arg.arg)
    return args


def _extract_function_source(lines: list[str], node: ast.FunctionDef) -> str:
    start = node.lineno - 1
    end = node.end_lineno if hasattr(node, "end_lineno") else start + 20
    return "\n".join(lines[start:end])

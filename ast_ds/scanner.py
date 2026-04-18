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

    # Construir mapa de prefijos: archivo -> prefijo acumulado
    prefix_map = _build_prefix_map(files)

    endpoints = []
    for file in files:
        prefix = prefix_map.get(file, "")
        endpoints.extend(_scan_file(file, prefix))

    return endpoints


def _collect_files(config: Config) -> list[Path]:
    if config.is_dir:
        return sorted(config.target.rglob("*.py"))
    else:
        return [config.target]


def _build_prefix_map(files: list[Path]) -> dict[Path, str]:
    """
    Lee todos los router.py y construye un mapa
    {archivo: prefijo_acumulado} para cada archivo Python.
    """
    prefix_map: dict[Path, str] = {}

    # Buscar todos los router.py en las carpetas escaneadas
    router_files = [f for f in files if f.name == "router.py"]

    for router_file in router_files:
        _extract_prefixes(router_file, prefix_map, files)

    return prefix_map


def _extract_prefixes(
    router_file: Path,
    prefix_map: dict[Path, str],
    all_files: list[Path],
    accumulated: str = "",
):
    """
    Analiza un router.py buscando include_router(x.router, prefix="/algo")
    y mapea el prefijo acumulado a cada archivo destino.
    """
    try:
        source = router_file.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Buscar router.include_router(...)
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr != "include_router":
            continue

        # Extraer prefix del keyword argument
        prefix = ""
        for kw in node.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                prefix = str(kw.value.value)
                break

        full_prefix = accumulated + prefix

        # Extraer el nombre del módulo del primer argumento
        # include_router(farm.router, ...) → "farm"
        if not node.args:
            continue

        first_arg = node.args[0]
        module_name = _extract_module_name(first_arg)
        if not module_name:
            continue

        # Buscar el archivo correspondiente al módulo
        target_file = _find_file(module_name, router_file.parent, all_files)
        if target_file is None:
            continue

        # Si es otro router.py, continuar recursivamente
        if target_file.name == "router.py":
            _extract_prefixes(target_file, prefix_map, all_files, full_prefix)
        else:
            # Es un archivo de endpoints — mapear prefijo
            if target_file not in prefix_map:
                prefix_map[target_file] = full_prefix


def _extract_module_name(node: ast.expr) -> Optional[str]:
    """
    Extrae el nombre del módulo de un nodo AST.
    farm.router → "farm"
    Sampling.router → "Sampling"
    """
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            return node.value.id
    if isinstance(node, ast.Name):
        return node.id
    return None


def _find_file(
    module_name: str,
    base_dir: Path,
    all_files: list[Path],
) -> Optional[Path]:
    """
    Busca el archivo Python correspondiente al nombre del módulo.
    """
    # Buscar exacto: farm.py, Sampling.py, router.py
    candidates = [
        base_dir / f"{module_name}.py",
        base_dir / module_name / "router.py",
        base_dir / module_name / "__init__.py",
    ]
    for candidate in candidates:
        if candidate in all_files:
            return candidate
        if candidate.exists():
            return candidate

    # Buscar en todos los archivos por nombre
    for f in all_files:
        if f.stem == module_name:
            return f

    return None


def _scan_file(file: Path, prefix: str = "") -> list[Endpoint]:
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

            full_path = prefix + route_path

            args = _extract_args(node)
            func_source = _extract_function_source(lines, node)

            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=full_path,
                    function_name=node.name,
                    source_file=file,
                    lineno=node.lineno,
                    args=args,
                    source_code=func_source,
                )
            )

    return endpoints


def _extract_route(decorator: ast.expr) -> tuple[Optional[str], str]:
    if not isinstance(decorator, ast.Call):
        return None, ""

    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None, ""

    method = func.attr.lower()
    if method not in HTTP_METHODS:
        return None, ""

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

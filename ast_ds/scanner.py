import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import Config

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


@dataclass
class ArgInfo:
    name: str
    annotation: Optional[str] = None   # nombre del tipo, ej: "CreateFarmInCmd"
    is_pydantic: bool = False           # si es un modelo Pydantic
    source_file: Optional[Path] = None  # archivo donde está definido el modelo


@dataclass
class Endpoint:
    method: str
    path: str
    function_name: str
    source_file: Path
    lineno: int
    args: list[str] = field(default_factory=list)
    arg_infos: list[ArgInfo] = field(default_factory=list)
    source_code: Optional[str] = None
    enum_map: dict[str, str] = field(default_factory=dict)  # enums del proyecto


def scan(config: Config) -> list[Endpoint]:
    files = _collect_files(config)
    prefix_map = _build_prefix_map(files)

    schema_files = _collect_schema_files(config)
    all_files_for_pydantic = files + [f for f in schema_files if f not in files]

    pydantic_map = _build_pydantic_map(all_files_for_pydantic)
    enum_map = build_enum_map(all_files_for_pydantic)

    endpoints = []
    for file in files:
        prefix = prefix_map.get(file, "")
        endpoints.extend(_scan_file(file, prefix, pydantic_map, enum_map))

    return endpoints


def _collect_schema_files(config: Config) -> list[Path]:
    """Recopila archivos Python de la carpeta de schemas si está configurada."""
    if config.schemas is None:
        return []
    if config.schemas.is_dir():
        return sorted(config.schemas.rglob("*.py"))
    return []


def _collect_files(config: Config) -> list[Path]:
    if config.is_dir:
        return sorted(config.target.rglob("*.py"))
    else:
        return [config.target]


def _build_pydantic_map(files: list[Path]) -> dict[str, Path]:
    """
    Escanea todos los archivos y construye un mapa
    {NombreModelo: archivo_donde_esta_definido} para clases que heredan
    de BaseModel — incluyendo detección transitiva (CustomBaseModel, etc).
    """
    PYDANTIC_ROOTS = {"BaseModel", "Schema", "SQLModel", "BaseSettings"}

    # Paso 1: detectar aliases de BaseModel via imports
    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if "pydantic" in module or "sqlmodel" in module:
                    for alias in node.names:
                        original = alias.name
                        imported_as = alias.asname or alias.name
                        if original in PYDANTIC_ROOTS:
                            PYDANTIC_ROOTS.add(imported_as)

    # Paso 2: recopilar todas las clases y sus bases
    class_bases: dict[str, list[str]] = {}
    class_file: dict[str, Path] = {}

    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    bases.append(base.id)
                elif isinstance(base, ast.Attribute):
                    bases.append(base.attr)
            class_bases[node.name] = bases
            class_file[node.name] = file

    # Paso 3: detección transitiva
    pydantic_classes: set[str] = set(PYDANTIC_ROOTS)
    changed = True
    while changed:
        changed = False
        for cls_name, bases in class_bases.items():
            if cls_name not in pydantic_classes:
                if any(b in pydantic_classes for b in bases):
                    pydantic_classes.add(cls_name)
                    changed = True

    # Paso 4: mapa final
    pydantic_map: dict[str, Path] = {}
    for cls_name in pydantic_classes:
        if cls_name in PYDANTIC_ROOTS:
            continue
        if cls_name in class_file:
            pydantic_map[cls_name] = class_file[cls_name]

    return pydantic_map


def build_enum_map(files: list[Path]) -> dict[str, str]:
    """
    Escanea archivos buscando clases que hereden de TextChoices, IntegerChoices,
    Enum, IntEnum, o str+Enum. Devuelve {NombreEnum: primer_valor} sin importar Django.
    """
    ENUM_BASES = {"TextChoices", "IntegerChoices", "Enum", "IntEnum", "StrEnum"}
    enum_map: dict[str, str] = {}

    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Verificar si hereda de alguna base de enum
            is_enum = False
            for base in node.bases:
                base_name = ""
                if isinstance(base, ast.Name):
                    base_name = base.id
                elif isinstance(base, ast.Attribute):
                    base_name = base.attr
                if base_name in ENUM_BASES:
                    is_enum = True
                    break

            if not is_enum:
                continue

            # Extraer el primer valor del enum
            for item in node.body:
                # NAME = "value"  o  NAME = "value", "label"
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if not isinstance(target, ast.Name):
                            continue
                        if target.id.startswith("_"):
                            continue
                        # Valor directo: NAME = "value"
                        if isinstance(item.value, ast.Constant):
                            enum_map[node.name] = str(item.value.value)
                            break
                        # Tuple: NAME = "value", "Label"
                        if isinstance(item.value, ast.Tuple):
                            elts = item.value.elts
                            if elts and isinstance(elts[0], ast.Constant):
                                enum_map[node.name] = str(elts[0].value)
                                break
                    if node.name in enum_map:
                        break

    return enum_map


def _build_prefix_map(files: list[Path]) -> dict[Path, str]:
    prefix_map: dict[Path, str] = {}
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
    try:
        source = router_file.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr != "include_router":
            continue

        prefix = ""
        for kw in node.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                prefix = str(kw.value.value)
                break

        full_prefix = accumulated + prefix

        if not node.args:
            continue

        first_arg = node.args[0]
        module_name = _extract_module_name(first_arg)
        if not module_name:
            continue

        target_file = _find_file(module_name, router_file.parent, all_files)
        if target_file is None:
            continue

        if target_file.name == "router.py":
            _extract_prefixes(target_file, prefix_map, all_files, full_prefix)
        else:
            if target_file not in prefix_map:
                prefix_map[target_file] = full_prefix


def _extract_module_name(node: ast.expr) -> Optional[str]:
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

    for f in all_files:
        if f.stem == module_name:
            return f

    return None


def _scan_file(
    file: Path,
    prefix: str = "",
    pydantic_map: dict[str, Path] = {},
    enum_map: dict[str, str] = {},
) -> list[Endpoint]:
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
            args, arg_infos = _extract_args(node, pydantic_map)
            func_source = _extract_function_source(lines, node)

            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=full_path,
                    function_name=node.name,
                    source_file=file,
                    lineno=node.lineno,
                    args=args,
                    arg_infos=arg_infos,
                    source_code=func_source,
                    enum_map=enum_map,
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


def _extract_args(
    func_node: ast.FunctionDef,
    pydantic_map: dict[str, Path],
) -> tuple[list[str], list[ArgInfo]]:
    """
    Extrae nombres y tipos de los argumentos.
    Devuelve (lista_nombres, lista_ArgInfo).
    """
    SKIP = {"self", "request", "response", "db", "session"}
    FASTAPI_DEPS = {"Depends", "Security", "BackgroundTasks"}

    args = []
    arg_infos = []

    for arg in func_node.args.args:
        if arg.arg in SKIP:
            continue

        # Detectar si es un Depends() — saltar
        if arg.annotation is not None:
            ann_str = ast.unparse(arg.annotation)
            if any(dep in ann_str for dep in FASTAPI_DEPS):
                continue

        annotation_name = None
        is_pydantic = False
        model_file = None

        if arg.annotation is not None:
            ann_str = ast.unparse(arg.annotation)
            # Nombre simple del tipo (sin Optional[], List[], etc.)
            base_type = ann_str.split("[")[0].strip()
            annotation_name = base_type

            # Verificar si es un modelo Pydantic conocido
            if base_type in pydantic_map:
                is_pydantic = True
                model_file = pydantic_map[base_type]

        args.append(arg.arg)
        arg_infos.append(
            ArgInfo(
                name=arg.arg,
                annotation=annotation_name,
                is_pydantic=is_pydantic,
                source_file=model_file,
            )
        )

    return args, arg_infos


def _extract_function_source(lines: list[str], node: ast.FunctionDef) -> str:
    start = node.lineno - 1
    end = node.end_lineno if hasattr(node, "end_lineno") else start + 20
    return "\n".join(lines[start:end])

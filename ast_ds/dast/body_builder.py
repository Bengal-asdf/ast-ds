"""
body_builder.py
Construye bodies de request válidos para endpoints FastAPI
importando dinámicamente los modelos Pydantic del proyecto objetivo.
Soporta modelos anidados, enums, UUID, Optional, y herencia de BaseModel.
"""
import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Optional

# ── Valores de prueba por tipo JSON Schema ────────────────────────────────────

def _default_for_format(fmt: Optional[str], field_name: str = "") -> Any:
    """Devuelve un valor de prueba según el format del JSON Schema."""
    name = field_name.lower()
    if fmt == "uuid":
        return "00000000-0000-0000-0000-000000000001"
    if fmt in ("date-time", "datetime"):
        return "2024-01-01T00:00:00"
    if fmt == "date":
        return "2024-01-01"
    if fmt == "email":
        return "test@example.com"
    if fmt == "uri" or fmt == "url":
        return "http://example.com"
    if fmt == "decimal":
        return 1.0
    return None


def _default_for_type(type_str: str, field_name: str = "") -> Any:
    """Devuelve un valor de prueba según el type del JSON Schema."""
    name = field_name.lower()
    if type_str == "string":
        if "email" in name:
            return "test@example.com"
        if "url" in name or "link" in name:
            return "http://example.com"
        if "date" in name:
            return "2024-01-01"
        if "name" in name or "title" in name:
            return "test_value"
        if "description" in name or "notes" in name:
            return "test description"
        return "test_string"
    if type_str == "integer":
        if "id" in name:
            return 1
        if "count" in name or "qty" in name or "quantity" in name:
            return 1
        return 1
    if type_str == "number":
        if "price" in name or "amount" in name or "weight" in name or "area" in name:
            return 10.0
        return 1.0
    if type_str == "boolean":
        return True
    if type_str == "array":
        return []
    if type_str == "object":
        return {}
    if type_str == "null":
        return None
    return "test"


# ── Construcción recursiva desde JSON Schema ──────────────────────────────────

def _build_from_schema(
    schema: dict,
    defs: dict,
    field_name: str = "",
    enum_map: dict[str, str] = {},
) -> Any:
    """
    Construye recursivamente un valor de prueba a partir de un JSON Schema.
    Resuelve $ref, anyOf, allOf, enum, y tipos anidados automáticamente.
    enum_map: valores de enums Django extraídos por AST.
    """
    # Resolver $ref
    if "$ref" in schema:
        ref_key = schema["$ref"].split("/")[-1]
        # Verificar si el ref es un enum conocido del proyecto
        if ref_key in enum_map:
            return enum_map[ref_key]
        if ref_key in defs:
            return _build_from_schema(defs[ref_key], defs, field_name, enum_map)
        return "test"

    # anyOf / oneOf
    for combiner in ("anyOf", "oneOf"):
        if combiner in schema:
            for option in schema[combiner]:
                if option.get("type") != "null":
                    return _build_from_schema(option, defs, field_name, enum_map)
            return None

    # allOf
    if "allOf" in schema:
        result = {}
        for sub in schema["allOf"]:
            val = _build_from_schema(sub, defs, field_name, enum_map)
            if isinstance(val, dict):
                result.update(val)
        return result if result else "test"

    # Enum inline
    if "enum" in schema:
        return schema["enum"][0]

    if "const" in schema:
        return schema["const"]

    schema_type = schema.get("type")
    fmt = schema.get("format")

    # Objeto con propiedades
    if schema_type == "object" or "properties" in schema:
        obj = {}
        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            obj[prop_name] = _build_from_schema(prop_schema, defs, prop_name, enum_map)
        return obj

    if fmt:
        val = _default_for_format(fmt, field_name)
        if val is not None:
            return val

    if schema_type:
        if isinstance(schema_type, list):
            for t in schema_type:
                if t != "null":
                    return _default_for_type(t, field_name)
            return None
        return _default_for_type(schema_type, field_name)

    return "test"


# ── Importación dinámica del modelo ──────────────────────────────────────────

def _find_project_root(file: Path) -> Optional[Path]:
    current = file.parent
    for _ in range(8):
        if any((current / f).exists() for f in ("pyproject.toml", "setup.py", "manage.py")):
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def _import_model(model_name: str, model_file: Path) -> Optional[type]:
    """Importa dinámicamente la clase del modelo desde el archivo fuente."""
    try:
        project_root = _find_project_root(model_file)
        if project_root:
            root_str = str(project_root)
            if root_str not in sys.path:
                sys.path.insert(0, root_str)

        module_name = f"_ast_ds_{model_file.stem}_{model_name}"
        spec = importlib.util.spec_from_file_location(module_name, model_file)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        # Evitar re-importar si ya está en caché
        if module_name not in sys.modules:
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)  # type: ignore
            except Exception:
                del sys.modules[module_name]
                return None

        return getattr(sys.modules[module_name], model_name, None)

    except Exception:
        return None


# ── Punto de entrada principal ────────────────────────────────────────────────

def build_body(
    model_name: Optional[str],
    model_file: Optional[Path],
    enum_map: Optional[dict[str, str]] = None,
) -> Optional[dict[str, Any]]:
    """
    Construye un body de request válido para un modelo Pydantic.
    enum_map: {NombreEnum: primer_valor} extraído por AST sin importar Django.
    """
    if model_name is None or model_file is None:
        return None

    _enum_map = enum_map or {}

    # ── Estrategia 1: importar y usar model_json_schema ──────────────────────
    model_class = _import_model(model_name, model_file)
    if model_class is not None:
        try:
            if hasattr(model_class, "model_json_schema"):
                schema = model_class.model_json_schema()
                defs = schema.get("$defs", {})
                body = _build_from_schema(schema, defs, model_name, _enum_map)
                if isinstance(body, dict) and body:
                    return body

            elif hasattr(model_class, "schema"):
                schema = model_class.schema()
                defs = schema.get("definitions", {})
                body = _build_from_schema(schema, defs, model_name, _enum_map)
                if isinstance(body, dict) and body:
                    return body

        except Exception:
            pass

    # ── Estrategia 2: parsear AST (fallback) ─────────────────────────────────
    return _build_from_ast(model_name, model_file, _enum_map)


def _build_from_ast(
    model_name: str,
    model_file: Path,
    enum_map: dict[str, str] = {},
) -> Optional[dict[str, Any]]:
    """Fallback: parsea el AST sin importar el módulo."""
    try:
        source = model_file.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return None

    class_map: dict[str, dict] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        fields = {}
        for item in node.body:
            if not isinstance(item, ast.AnnAssign):
                continue
            if not isinstance(item.target, ast.Name):
                continue
            field_name = item.target.id
            type_str = ast.unparse(item.annotation) if item.annotation else "str"
            if item.value is not None:
                try:
                    fields[field_name] = ast.literal_eval(item.value)
                    continue
                except (ValueError, TypeError):
                    pass
            fields[field_name] = _ast_default(field_name, type_str, class_map, enum_map)
        class_map[node.name] = fields

    return class_map.get(model_name)


def _ast_default(
    field_name: str,
    type_str: str,
    class_map: dict,
    enum_map: dict[str, str] = {},
) -> Any:
    """Asigna valor de prueba desde el string del tipo."""
    name = field_name.lower()
    clean = type_str.replace("Optional[", "").replace("]", "").strip()
    if clean in enum_map:
        return enum_map[clean]
    if clean in class_map:
        return class_map[clean]
    if "UUID" in type_str:
        return "00000000-0000-0000-0000-000000000001"
    if "datetime" in type_str:
        return "2024-01-01T00:00:00"
    if "date" in type_str:
        return "2024-01-01"
    if "float" in type_str or "Decimal" in type_str:
        return 1.0
    if "int" in type_str:
        return 1
    if "bool" in type_str:
        return True
    if "list" in type_str.lower() or "List" in type_str:
        return []
    if "email" in name:
        return "test@example.com"
    if "id" in name:
        return 1
    if "name" in name:
        return "test_value"
    if "area" in name or "weight" in name or "price" in name:
        return 1.0
    return "test_string"

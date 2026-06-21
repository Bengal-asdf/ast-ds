import ast
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..scanner import Endpoint


class Severity(str, Enum):
    CRITICAL = "CRÍTICO"
    HIGH = "ALTO"
    MEDIUM = "MEDIO"
    LOW = "BAJO"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    lineno: int
    owasp: str
    evidence: Optional[str] = None


def analyze(endpoint: Endpoint) -> list[Finding]:
    if not endpoint.source_code:
        return []

    try:
        tree = ast.parse(endpoint.source_code)
    except SyntaxError:
        return []

    findings = []
    findings.extend(_check_sql_injection(tree, endpoint.source_code))
    findings.extend(_check_missing_auth(tree, endpoint))
    findings.extend(_check_missing_input_validation(tree, endpoint))
    findings.extend(_check_hardcoded_secrets(tree))
    findings.extend(_check_broad_exception(tree))
    findings.extend(_check_bola(tree, endpoint))
    findings.extend(_check_resource_consumption(tree, endpoint))
    findings.extend(_check_function_level_auth(tree, endpoint))
    findings.extend(_check_ssrf(tree))
    findings.extend(_check_inventory(tree, endpoint))
    findings.extend(_check_sensitive_business_flow(tree, endpoint))
    findings.extend(_check_unsafe_api_consumption(tree, endpoint))

    return findings


# ── REGLA 1: SQL Injection ────────────────────────────────────────────────────
def _check_sql_injection(tree: ast.AST, source: str) -> list[Finding]:
    findings = []
    sql_keywords = ("select", "insert", "update", "delete", "from", "where")

    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            node_source = ast.unparse(node).lower()
            if any(kw in node_source for kw in sql_keywords):
                findings.append(
                    Finding(
                        rule_id="SAST-001",
                        title="Posible SQL Injection",
                        description="Se detectó concatenación de strings en lo que parece una query SQL.",
                        severity=Severity.CRITICAL,
                        lineno=node.lineno if hasattr(node, "lineno") else 0,
                        owasp="API8:2023 — Security Misconfiguration",
                        evidence=ast.unparse(node)[:120],
                    )
                )

        if isinstance(node, ast.JoinedStr):
            node_source = ast.unparse(node).lower()
            if any(kw in node_source for kw in sql_keywords):
                findings.append(
                    Finding(
                        rule_id="SAST-001",
                        title="Posible SQL Injection via f-string",
                        description="Se detectó un f-string que construye una query SQL con variables.",
                        severity=Severity.CRITICAL,
                        lineno=node.lineno if hasattr(node, "lineno") else 0,
                        owasp="API8:2023 — Security Misconfiguration",
                        evidence=ast.unparse(node)[:120],
                    )
                )

    return findings


# ── REGLA 2: Ausencia de autenticación ───────────────────────────────────────
def _check_missing_auth(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    auth_keywords = (
        "current_user",
        "get_current_user",
        "verify_token",
        "oauth2_scheme",
        "security",
        "authorize",
        "token",
        "Depends",
        "HTTPBearer",
        "APIKeyHeader",
    )

    source_lower = (endpoint.source_code or "").lower()
    has_auth = any(kw.lower() in source_lower for kw in auth_keywords)

    if not has_auth and endpoint.method in ("POST", "PUT", "PATCH", "DELETE"):
        return [
            Finding(
                rule_id="SAST-002",
                title="Ausencia de control de autenticación",
                description=(
                    f"El endpoint {endpoint.method} {endpoint.path} no presenta "
                    "mecanismos de autenticación detectables."
                ),
                severity=Severity.HIGH,
                lineno=1,
                owasp="API2:2023 — Broken Authentication",
            )
        ]

    return []


# ── REGLA 3: Ausencia de validación de entrada ────────────────────────────────
def _check_missing_input_validation(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    findings = []
    pydantic_types = ("BaseModel", "Field", "validator", "model_validator")
    source = endpoint.source_code or ""

    has_pydantic = any(t in source for t in pydantic_types)

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for arg in node.args.args:
            if arg.arg in ("self", "request", "response", "db", "session"):
                continue
            if arg.annotation is None and not has_pydantic:
                findings.append(
                    Finding(
                        rule_id="SAST-003",
                        title="Parámetro sin validación de tipo",
                        description=(
                            f"El parámetro '{arg.arg}' no tiene anotación de tipo ni "
                            "modelo Pydantic asociado."
                        ),
                        severity=Severity.MEDIUM,
                        lineno=arg.col_offset,
                        owasp="API3:2023 — Broken Object Property Level Authorization",
                        evidence=f"def {node.name}(..., {arg.arg}, ...)",
                    )
                )

    return findings


# ── REGLA 4: Secrets hardcodeados ────────────────────────────────────────────
def _check_hardcoded_secrets(tree: ast.AST) -> list[Finding]:
    findings = []
    secret_keywords = (
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "auth",
        "private_key",
        "credentials",
    )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id.lower()
            if any(kw in var_name for kw in secret_keywords):
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, str
                ):
                    if len(node.value.value) > 4:
                        findings.append(
                            Finding(
                                rule_id="SAST-004",
                                title="Secret hardcodeado detectado",
                                description=(
                                    f"La variable '{target.id}' parece contener "
                                    "un valor sensible hardcodeado."
                                ),
                                severity=Severity.CRITICAL,
                                lineno=node.lineno,
                                owasp="API8:2023 — Security Misconfiguration",
                                evidence=f"{target.id} = '***'",
                            )
                        )

    return findings


# ── REGLA 5: Manejo amplio de excepciones ────────────────────────────────────
def _check_broad_exception(tree: ast.AST) -> list[Finding]:
    findings = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            findings.append(
                Finding(
                    rule_id="SAST-005",
                    title="Manejo genérico de excepciones",
                    description=(
                        "Se usa 'except:' sin especificar el tipo de excepción. "
                        "Puede ocultar errores de seguridad."
                    ),
                    severity=Severity.LOW,
                    lineno=node.lineno,
                    owasp="API8:2023 — Security Misconfiguration",
                    evidence="except: (sin tipo específico)",
                )
            )

    return findings


# ── REGLA 6: BOLA — Broken Object Level Authorization (API1:2023) ─────────────
def _check_bola(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta patrones de BOLA: el endpoint recibe un ID de objeto como parámetro
    de ruta o cuerpo pero no realiza una verificación explícita de propiedad
    (no compara user_id / owner_id con el usuario autenticado).
    """
    findings = []

    # Buscar parámetros que parezcan IDs de objeto en la ruta
    id_pattern = re.compile(r"\{(\w*id\w*|\w*_id|\w*Id)\}", re.IGNORECASE)
    path_ids = id_pattern.findall(endpoint.path)
    if not path_ids:
        return []

    source = endpoint.source_code or ""
    source_lower = source.lower()

    # Indicadores de que se hace verificación de propiedad
    ownership_checks = (
        "user_id",
        "owner_id",
        "current_user.id",
        "current_user['id']",
        "== user",
        "!= user",
        "forbidden",
        "raise httpexception",
        "status.http_403",
        "403",
    )
    has_ownership_check = any(kw in source_lower for kw in ownership_checks)

    # Indicadores de que hay autenticación (sin auth no aplica BOLA)
    auth_present = any(
        kw in source_lower
        for kw in ("current_user", "get_current_user", "depends", "token")
    )

    if auth_present and not has_ownership_check:
        findings.append(
            Finding(
                rule_id="SAST-006",
                title="Posible BOLA — Acceso a objeto sin verificación de propiedad",
                description=(
                    f"El endpoint recibe el identificador '{path_ids[0]}' en la ruta "
                    "pero no verifica que el objeto pertenezca al usuario autenticado."
                ),
                severity=Severity.CRITICAL,
                lineno=1,
                owasp="API1:2023 — Broken Object Level Authorization",
                evidence=f"Path param: {path_ids[0]} | Sin comparación owner/user",
            )
        )

    return findings


# ── REGLA 7: Unrestricted Resource Consumption (API4:2023) ───────────────────
def _check_resource_consumption(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta ausencia de límites en parámetros de paginación o tamaño de recursos
    (limit, page_size, count, offset) sin validación de rango máximo.
    """
    findings = []
    pagination_params = {"limit", "page_size", "count", "size", "per_page", "top"}
    source = endpoint.source_code or ""
    source_lower = source.lower()

    # Solo si el endpoint tiene parámetros de paginación
    has_pagination = any(p in source_lower for p in pagination_params)
    if not has_pagination:
        return []

    # Buscar si hay validación de rango (Field con le/ge, validators, conint)
    range_validators = (
        "field(",
        "le=",
        "ge=",
        "gt=",
        "lt=",
        "max_",
        "conint",
        "validator",
        "assert",
        "if limit",
        "if size",
        "if count",
        "if page_size",
    )
    has_range_check = any(v in source_lower for v in range_validators)

    if not has_range_check:
        findings.append(
            Finding(
                rule_id="SAST-007",
                title="Consumo de recursos sin límite máximo",
                description=(
                    "El endpoint acepta parámetros de paginación o tamaño "
                    "(limit/size/count) sin validar un valor máximo permitido. "
                    "Un atacante puede solicitar volúmenes arbitrarios de datos."
                ),
                severity=Severity.MEDIUM,
                lineno=1,
                owasp="API4:2023 — Unrestricted Resource Consumption",
                evidence="Parámetro de paginación sin Field(le=...) ni validación de rango",
            )
        )

    return findings


# ── REGLA 8: Broken Function Level Authorization (API5:2023) ─────────────────
def _check_function_level_auth(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta endpoints administrativos o privilegiados que no verifican
    el rol o nivel de privilegio del usuario autenticado.
    """
    findings = []

    admin_patterns = re.compile(
        r"/(admin|management|internal|superuser|staff|backoffice|ops|system)",
        re.IGNORECASE,
    )
    if not admin_patterns.search(endpoint.path):
        return []

    source_lower = (endpoint.source_code or "").lower()

    role_checks = (
        "is_admin",
        "is_superuser",
        "role",
        "permission",
        "has_permission",
        "require_role",
        "check_role",
        "admin",
        "superuser",
        "staff",
        "scope",
    )
    has_role_check = any(kw in source_lower for kw in role_checks)

    if not has_role_check:
        findings.append(
            Finding(
                rule_id="SAST-008",
                title="Endpoint privilegiado sin verificación de rol",
                description=(
                    f"La ruta '{endpoint.path}' sugiere funcionalidad administrativa "
                    "pero no contiene verificación de rol o nivel de privilegio."
                ),
                severity=Severity.HIGH,
                lineno=1,
                owasp="API5:2023 — Broken Function Level Authorization",
                evidence=f"Ruta: {endpoint.path} | Sin comprobación de rol/permiso",
            )
        )

    return findings


# ── REGLA 9: SSRF — Server Side Request Forgery (API7:2023) ─────────────────
def _check_ssrf(tree: ast.AST) -> list[Finding]:
    """
    Detecta llamadas HTTP salientes donde la URL se construye total o parcialmente
    con datos controlados por el usuario (parámetros de función).
    """
    findings = []

    # Nombres de funciones/métodos que realizan requests HTTP salientes
    http_callers = {
        "get", "post", "put", "patch", "delete", "request", "fetch",
        "urlopen", "urlretrieve", "open",
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Detectar httpx.get(url), requests.get(url), urllib.request.urlopen(url)
        func = node.func
        caller_name = None
        if isinstance(func, ast.Attribute) and func.attr.lower() in http_callers:
            caller_name = func.attr
        elif isinstance(func, ast.Name) and func.id.lower() in http_callers:
            caller_name = func.id

        if caller_name is None:
            continue

        # Verificar si el primer argumento de la URL contiene una variable
        if not node.args:
            continue

        first_arg = node.args[0]

        # URL construida con f-string o concatenación: riesgo de SSRF
        is_dynamic_url = isinstance(first_arg, ast.JoinedStr) or (
            isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add)
        )

        # URL que es directamente un parámetro de función
        is_param_url = isinstance(first_arg, ast.Name)

        if is_dynamic_url or is_param_url:
            evidence = ast.unparse(first_arg)[:100]
            findings.append(
                Finding(
                    rule_id="SAST-009",
                    title="Posible SSRF — URL controlada por el usuario",
                    description=(
                        f"Se detectó una llamada HTTP saliente ({caller_name}) cuya URL "
                        "se construye con datos potencialmente controlados por el usuario. "
                        "Sin validación de destino, un atacante puede redirigir requests "
                        "a servicios internos."
                    ),
                    severity=Severity.HIGH,
                    lineno=node.lineno if hasattr(node, "lineno") else 0,
                    owasp="API7:2023 — Server Side Request Forgery",
                    evidence=f"{caller_name}({evidence})",
                )
            )

    return findings


# ── REGLA 10: Improper Inventory Management (API9:2023) ──────────────────────
def _check_inventory(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta indicadores de endpoints no documentados, en versiones antiguas,
    de debug/test, o con rutas que sugieren exposición accidental.
    """
    findings = []

    inventory_patterns = re.compile(
        r"/(v[0-9]+|beta|alpha|test|debug|dev|deprecated|legacy|old|tmp|internal|private)",
        re.IGNORECASE,
    )

    match = inventory_patterns.search(endpoint.path)
    if not match:
        return []

    segment = match.group(1).lower()

    if segment.startswith("v") and segment[1:].isdigit():
        # Versión numérica: verificar si hay versión más nueva implícita
        # Solo reportar si es v0 o si el código tiene comentarios de deprecación
        version_num = int(segment[1:])
        source_lower = (endpoint.source_code or "").lower()
        is_deprecated = any(
            kw in source_lower
            for kw in ("deprecated", "legacy", "old", "will be removed", "obsolete")
        )
        if version_num == 0 or is_deprecated:
            findings.append(
                Finding(
                    rule_id="SAST-010",
                    title="Endpoint en versión obsoleta o deprecada",
                    description=(
                        f"La ruta '{endpoint.path}' expone una versión de API potencialmente "
                        "obsoleta. Los endpoints deprecados pueden carecer de controles "
                        "de seguridad actualizados."
                    ),
                    severity=Severity.LOW,
                    lineno=1,
                    owasp="API9:2023 — Improper Inventory Management",
                    evidence=f"Ruta: {endpoint.path}",
                )
            )
    else:
        # Segmentos de debug/test/internal
        findings.append(
            Finding(
                rule_id="SAST-010",
                title="Endpoint de diagnóstico o acceso interno expuesto",
                description=(
                    f"La ruta '{endpoint.path}' contiene el segmento '/{segment}' que "
                    "sugiere un endpoint de debug, testing o acceso interno expuesto "
                    "en el entorno analizado."
                ),
                severity=Severity.MEDIUM,
                lineno=1,
                owasp="API9:2023 — Improper Inventory Management",
                evidence=f"Segmento detectado: /{segment}",
            )
        )

    return findings


# ── REGLA 11: Unrestricted Access to Sensitive Business Flows (API6:2023) ─────
def _check_sensitive_business_flow(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta endpoints que exponen flujos de negocio críticos (registro masivo,
    exportación de datos, generación de reportes, operaciones batch) sin controles
    de rate limiting, throttling o anti-abuso detectables en el código.
    """
    findings = []

    # Patrones en la ruta que indican flujo de negocio sensible
    sensitive_path_patterns = re.compile(
        r"/(register|signup|export|report|bulk|batch|import|"
        r"download|generate|upload|send|notify|subscribe|checkout|order|invoice)",
        re.IGNORECASE,
    )

    if not sensitive_path_patterns.search(endpoint.path):
        return []

    source_lower = (endpoint.source_code or "").lower()

    # Indicadores de rate limiting o throttling
    rate_limit_indicators = (
        "ratelimit",
        "rate_limit",
        "throttle",
        "slowapi",
        "limiter",
        "x-ratelimit",
        "too_many_requests",
        "429",
        "cooldown",
        "backoff",
        "max_attempts",
        "captcha",
        "recaptcha",
    )

    has_rate_limit = any(ind in source_lower for ind in rate_limit_indicators)

    if not has_rate_limit:
        match = sensitive_path_patterns.search(endpoint.path)
        segment = match.group(1) if match else endpoint.path

        findings.append(
            Finding(
                rule_id="SAST-011",
                title="Flujo de negocio sensible sin control de rate limiting",
                description=(
                    f"El endpoint '{endpoint.path}' expone un flujo de negocio crítico "
                    f"('{segment}') sin controles de rate limiting, throttling o "
                    "mecanismos anti-abuso detectables. Un atacante podría automatizar "
                    "solicitudes masivas para abusar del flujo."
                ),
                severity=Severity.HIGH,
                lineno=1,
                owasp="API6:2023 — Unrestricted Access to Sensitive Business Flows",
                evidence=f"Ruta sensible: {endpoint.path} | Sin rate limiting detectado",
            )
        )

    return findings


# ── REGLA 12: Unsafe Consumption of APIs (API10:2023) ────────────────────────
def _check_unsafe_api_consumption(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta cuando el endpoint consume APIs externas (httpx, requests, urllib)
    y usa la respuesta directamente sin validar el status code, el tipo de contenido,
    ni el esquema de datos recibido (confianza ciega en terceros).
    """
    findings = []

    http_clients = {"httpx", "requests", "urllib", "aiohttp", "httplib"}
    response_validators = (
        "raise_for_status",
        "status_code",
        "response.ok",
        ".ok",
        "assert ",
        "if resp",
        "if response",
        "json_schema",
        "validate",
        "pydantic",
        "basemodel",
    )

    source_lower = (endpoint.source_code or "").lower()

    # Verificar si hay llamadas a clientes HTTP externos
    has_http_client = any(client in source_lower for client in http_clients)
    if not has_http_client:
        return []

    # Verificar si hay validación de la respuesta
    has_validation = any(v in source_lower for v in response_validators)

    if not has_validation:
        findings.append(
            Finding(
                rule_id="SAST-012",
                title="Consumo inseguro de API externa sin validación de respuesta",
                description=(
                    "El endpoint realiza llamadas a APIs externas pero no valida "
                    "el status code ni el esquema de la respuesta antes de procesarla. "
                    "Datos maliciosos o inesperados de terceros pueden propagarse "
                    "al sistema sin control."
                ),
                severity=Severity.MEDIUM,
                lineno=1,
                owasp="API10:2023 — Unsafe Consumption of APIs",
                evidence="Cliente HTTP externo detectado sin raise_for_status() ni validación de esquema",
            )
        )

    return findings

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
    findings.extend(_check_ssrf(tree, endpoint))
    findings.extend(_check_inventory(tree, endpoint))
    findings.extend(_check_sensitive_business_flow(tree, endpoint))
    findings.extend(_check_unsafe_api_consumption(tree, endpoint))

    # Deduplicar hallazgos por rule_id — evitar múltiples nodos AST del mismo patrón
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.rule_id, f.lineno)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


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
    """
    Detecta ausencia de autenticación en endpoints de escritura.
    Busca indicadores en la firma de la función (anotaciones de parámetros)
    además del código fuente para evitar falsos positivos en endpoints seguros
    que usan Depends() pero cuyo nombre no aparece en el source_code del endpoint.
    """
    auth_keywords = (
        "current_user",
        "get_current_user",
        "verify_token",
        "oauth2_scheme",
        "security",
        "authorize",
        "token",
        "depends",
        "httpbearer",
        "apikeyheader",
        "security_scopes",
        "oauth2",
        "jwt",
    )

    if endpoint.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return []

    # Verificar en anotaciones de argumentos — Depends() registrado por el scanner
    for arg_info in (endpoint.arg_infos or []):
        ann = (arg_info.annotation or "").lower()
        if any(kw in ann for kw in auth_keywords):
            return []

    # Verificar en el cuerpo de la función (solo función, no imports)
    # Extraer solo el código de la función excluyendo el contexto global
    func_source = (endpoint.source_code or "").split("\n\n# ---")[0].lower()
    if any(kw in func_source for kw in auth_keywords):
        return []

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
            if arg.arg in ("self", "request", "response", "db", "session", "current_user"):
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



def _has_ownership_check_in_ast(tree: ast.AST, source_lower: str) -> bool:
    """
    Verifica si el código contiene una comparación real de propiedad
    (no solo la presencia del string "user_id" en un diccionario).
    Busca: comparaciones ==, !=, HTTPException 403, raise con forbidden.
    """
    # Buscar comparaciones con user_id/owner_id en el AST
    ownership_names = {"user_id", "owner_id", "current_user"}
    
    for node in ast.walk(tree):
        # Comparaciones: obj.user_id == current_user.id, order["user_id"] != user.id
        if isinstance(node, ast.Compare):
            node_str = ast.unparse(node).lower()
            if any(name in node_str for name in ownership_names):
                return True
        
        # HTTPException con 403
        if isinstance(node, ast.Call):
            call_str = ast.unparse(node).lower()
            if "httpexception" in call_str and "403" in call_str:
                return True
        
        # raise HTTPException(status_code=403)
        if isinstance(node, ast.Raise):
            raise_str = ast.unparse(node).lower()
            if "403" in raise_str or "forbidden" in raise_str:
                return True

    # Fallback: verificar patterns muy específicos en source
    specific_patterns = (
        "forbidden",
        "status_code=403",
        "http_403",
        "status.http_403",
    )
    return any(p in source_lower for p in specific_patterns)


# ── REGLA 6: BOLA — Broken Object Level Authorization (API1:2023) ─────────────
def _check_bola(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta BOLA en dos escenarios:
    1. Hay autenticación pero no se verifica propiedad del objeto
    2. El endpoint expone IDs de objeto sin ningún control de acceso
    """
    findings = []

    id_pattern = re.compile(r"\{(\w*id\w*|\w*_id|\w*Id)\}", re.IGNORECASE)
    path_ids = id_pattern.findall(endpoint.path)
    if not path_ids:
        return []

    source = endpoint.source_code or ""
    source_lower = source.lower()

    auth_keywords = (
        "current_user", "get_current_user", "depends", "token",
        "httpbearer", "oauth2", "security",
    )
    auth_present = any(kw in source_lower for kw in auth_keywords)

    # Verificación de propiedad — buscar comparaciones reales en el AST
    # no solo presencia de "user_id" como clave de diccionario
    has_ownership_check = _has_ownership_check_in_ast(tree, source_lower)

    # Escenario 1: hay auth pero no verifica propiedad
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

    # Escenario 2: no hay auth ni verificación — acceso completamente abierto
    if not auth_present and not has_ownership_check:
        findings.append(
            Finding(
                rule_id="SAST-006",
                title="BOLA — Objeto accesible sin autenticación ni control de propiedad",
                description=(
                    f"El endpoint expone el identificador '{path_ids[0]}' en la ruta "
                    "sin ningún mecanismo de autenticación ni verificación de propiedad. "
                    "Cualquier usuario puede acceder a objetos de otros usuarios."
                ),
                severity=Severity.CRITICAL,
                lineno=1,
                owasp="API1:2023 — Broken Object Level Authorization",
                evidence=f"Path param: {path_ids[0]} | Sin auth ni control de propiedad",
            )
        )

    return findings


# ── REGLA 7: Unrestricted Resource Consumption (API4:2023) ───────────────────
def _check_resource_consumption(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta parámetros de paginación sin restricción de rango máximo.
    Verifica explícitamente que Field(le=...) esté presente en el AST,
    no solo como string en el source code.
    """
    findings = []
    pagination_params = {"limit", "page_size", "count", "size", "per_page", "top"}
    source = endpoint.source_code or ""
    source_lower = source.lower()

    # Verificar que los parámetros de paginación sean argumentos reales del endpoint
    endpoint_arg_names = {arg.lower() for arg in (endpoint.args or [])}
    has_pagination = any(p in endpoint_arg_names for p in pagination_params)

    if not has_pagination:
        # Buscar en el cuerpo de la función — puede venir de modelo Pydantic
        # ej: pagination.limit, data.page_size
        # Usar word boundary para evitar coincidencias parciales (count en request_counts)
        import re as _re
        func_source_only = source_lower.split("\n\n# ---")[0]
        has_pagination = any(
            _re.search(rf"\.{p}\b|\b{p}\s*:", func_source_only)
            for p in pagination_params
        )
    if not has_pagination:
        return []

    # Buscar Field() con restricción le= o ge= en el AST de la función
    has_range_check = _has_field_with_range_constraint(tree)

    # Si el endpoint usa un modelo Pydantic, verificar en el código del modelo
    if not has_range_check:
        for arg_info in (endpoint.arg_infos or []):
            if arg_info.is_pydantic and arg_info.source_file is not None:
                try:
                    model_source = arg_info.source_file.read_text(encoding="utf-8")
                    model_tree = ast.parse(model_source)
                    if _has_field_with_range_constraint(model_tree):
                        has_range_check = True
                        break
                except Exception:
                    pass

    # También verificar en source como fallback
    if not has_range_check:
        func_source_only = source_lower.split("\n\n# ---")[0]
        range_indicators = (
            "conint", "validator", "assert",
            "if limit", "if size", "if count", "if page_size",
            "max_", "min_",
        )
        has_range_check = any(v in func_source_only for v in range_indicators)

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


def _has_field_with_range_constraint(tree: ast.AST) -> bool:
    """
    Verifica si existe una llamada Field(..., le=N) o Field(..., ge=N)
    en el AST — indicador seguro de que hay restricción de rango.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        func_name = None
        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr

        if func_name != "Field":
            continue

        for kw in node.keywords:
            if kw.arg in ("le", "ge", "gt", "lt", "max_length", "min_length"):
                return True

    return False


# ── REGLA 8: Broken Function Level Authorization (API5:2023) ─────────────────
def _check_function_level_auth(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta endpoints administrativos sin verificación de rol.
    Solo reporta si no hay ningún indicador de verificación de rol
    en la firma de la función ni en el código fuente.
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
        "has_permission",
        "require_role",
        "check_role",
        "scope",
        "permission",
    )
    has_role_check = any(kw in source_lower for kw in role_checks)

    # También verificar en anotaciones de argumentos
    for arg_info in (endpoint.arg_infos or []):
        ann = (arg_info.annotation or "").lower()
        if any(kw in ann for kw in role_checks):
            has_role_check = True
            break

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
def _check_ssrf(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    """
    Detecta llamadas HTTP salientes donde la URL viene directamente
    de un parámetro de entrada del endpoint (no de una constante interna).
    Evita falsos positivos en llamadas con URLs fijas o variables internas.
    """
    findings = []

    http_callers = {
        "get", "post", "put", "patch", "delete", "request", "fetch",
        "urlopen", "urlretrieve",
    }

    # Nombres de parámetros del endpoint que vienen del usuario
    user_params = {arg_info.name for arg_info in (endpoint.arg_infos or [])}
    user_params.update(endpoint.args or [])

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        caller_name = None
        http_client_names = {"httpx", "requests", "urllib", "aiohttp", "session", "client"}

        if isinstance(func, ast.Attribute) and func.attr.lower() in http_callers:
            # Verificar que el receptor sea un cliente HTTP conocido
            # y no un dict/list (.get() sobre diccionarios no es HTTP)
            receiver = func.value
            receiver_name = ""
            if isinstance(receiver, ast.Name):
                receiver_name = receiver.id.lower()
            elif isinstance(receiver, ast.Attribute):
                receiver_name = receiver.attr.lower()

            # Excluir .get() y .post() sobre objetos que no son clientes HTTP
            # Si el método es get/post/etc sobre un objeto desconocido, verificar contexto
            is_dict_method = func.attr.lower() in {"get"} and receiver_name not in http_client_names
            if is_dict_method:
                # Verificar si el receiver parece un dict (ej: fake_orders, data, config)
                # Si no es un cliente HTTP conocido y el método es .get(), probablemente es dict
                if receiver_name not in http_client_names and not any(
                    h in receiver_name for h in http_client_names
                ):
                    continue

            caller_name = func.attr
        elif isinstance(func, ast.Name) and func.id.lower() in http_callers:
            caller_name = func.id

        if caller_name is None:
            continue

        if not node.args:
            continue

        first_arg = node.args[0]

        # Verificar si hay validación de dominio en la función
        func_source_lower = (endpoint.source_code or "").split("\n\n# ---")[0].lower()
        domain_validators = (
            "allowed_domains", "whitelist", "allowlist",
            "urlparse", "netloc", "domain_check",
        )
        has_domain_validation = any(v in func_source_lower for v in domain_validators)

        if has_domain_validation:
            continue

        # Caso 1: URL es directamente un parámetro del endpoint
        is_user_param_url = (
            isinstance(first_arg, ast.Name) and
            first_arg.id in user_params
        )

        # Caso 2: URL es un atributo de un parámetro (data.url, body.target, etc.)
        is_attr_of_user_param = (
            isinstance(first_arg, ast.Attribute) and
            isinstance(first_arg.value, ast.Name) and
            first_arg.value.id in user_params
        )

        # Caso 3: f-string cuyo PRIMER segmento es un parámetro del usuario
        is_fstring_with_user_param = False
        if isinstance(first_arg, ast.JoinedStr) and first_arg.values:
            first_segment = first_arg.values[0]
            if isinstance(first_segment, ast.FormattedValue):
                inner = first_segment.value
                if isinstance(inner, ast.Name) and inner.id in user_params:
                    is_fstring_with_user_param = True
                elif isinstance(inner, ast.Attribute) and isinstance(inner.value, ast.Name):
                    if inner.value.id in user_params:
                        is_fstring_with_user_param = True

        # Caso 4: concatenación cuyo primer operando es parámetro del usuario
        is_concat_with_user_param = False
        if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
            left = first_arg.left
            if isinstance(left, ast.Name) and left.id in user_params:
                is_concat_with_user_param = True

        if is_user_param_url or is_attr_of_user_param or is_fstring_with_user_param or is_concat_with_user_param:
            evidence = ast.unparse(first_arg)[:100]
            findings.append(
                Finding(
                    rule_id="SAST-009",
                    title="Posible SSRF — URL controlada por el usuario",
                    description=(
                        f"Se detectó una llamada HTTP saliente ({caller_name}) cuya URL "
                        "se construye con datos directamente controlados por el usuario "
                        "sin validación de dominio de destino."
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
    Detecta flujos de negocio sensibles sin rate limiting.
    Verifica indicadores de rate limiting en el AST además del source code
    para evitar falsos positivos en endpoints con rate limiting implementado.
    """
    findings = []

    sensitive_path_patterns = re.compile(
        r"/(register|signup|export|report|bulk|batch|import|"
        r"download|generate|upload|send|notify|subscribe|checkout|invoice)",
        re.IGNORECASE,
    )

    if not sensitive_path_patterns.search(endpoint.path):
        return []

    source_lower = (endpoint.source_code or "").lower()

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
        "request_counts",
        "time.time",
        "time_window",
        "window",
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
    # Para SAST-012 usar solo la función, no el contexto global
    func_source_lower = source_lower.split("\n\n# ---")[0]

    has_http_client = any(client in func_source_lower for client in http_clients)
    if not has_http_client:
        return []

    has_validation = any(v in func_source_lower for v in response_validators)
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
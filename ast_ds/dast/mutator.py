from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

from ..config import AuthConfig
from ..dast.body_builder import build_body
from ..sast.analyzer import Finding, Severity
from ..scanner import Endpoint


class Status(str, Enum):
    CONFIRMED = "CONFIRMADO"
    POTENTIAL = "POTENCIAL"
    NOT_FOUND = "NO_DETECTADO"


@dataclass
class DastResult:
    endpoint: Endpoint
    finding: Finding
    status: Status
    payload: dict[str, Any]
    status_code: Optional[int] = None
    response_snippet: Optional[str] = None
    error: Optional[str] = None


# ── Payloads ──────────────────────────────────────────────────────────────────

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT null--",
    "1' AND SLEEP(2)--",
]

AUTH_BYPASS_PAYLOADS = [
    {"Authorization": ""},
    {"Authorization": "Bearer invalid_token"},
    {"Authorization": "Bearer null"},
    {},
]

FUZZING_PAYLOADS = [
    "",
    None,
    "A" * 5000,
    "<script>alert(1)</script>",
    "../../etc/passwd",
    0,
    -1,
    True,
    [],
]

RESOURCE_PAYLOADS = [
    {"limit": 999999},
    {"page_size": 999999},
    {"count": -1},
    {"size": 999999},
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://127.0.0.1:22",                             # localhost SSH
    "http://127.0.0.1:6379",                           # Redis
    "http://192.168.1.1",                              # red interna
    "file:///etc/passwd",                              # file:// scheme
    "http://0.0.0.0:80",
]

BOLA_ID_PAYLOADS = [
    "1", "2", "0", "-1", "99999999",
    "00000000-0000-0000-0000-000000000001",            # UUID de otro usuario
]


# ── Resolución de token de autenticación ──────────────────────────────────────

def _resolve_auth_headers(
    auth: Optional[AuthConfig],
    client: httpx.Client,
) -> dict[str, str]:
    """
    Devuelve las cabeceras de autenticación listas para usar en requests DAST.
    Soporta: token estático (jwt/bearer), OAuth2 password flow, API key.
    """
    if auth is None:
        return {}

    auth_type = auth.type.lower()

    # Token estático proporcionado directamente en config.yaml
    if auth.token:
        prefix = auth.prefix or "Bearer"
        return {auth.header: f"{prefix} {auth.token}"}

    # API Key
    if auth_type == "apikey" and auth.api_key:
        return {auth.header: auth.api_key}

    # OAuth2 / JWT dinámico: obtener token vía login_url
    if auth.login_url and auth.username and auth.password:
        try:
            resp = client.post(
                auth.login_url,
                json={
                    auth.username_field: auth.username,
                    auth.password_field: auth.password,
                },
                timeout=10,
            )
            if resp.status_code in (200, 201):
                body = resp.json()
                # Buscar el token en campos comunes
                token = (
                    body.get("access_token")
                    or body.get("token")
                    or body.get("id_token")
                    or body.get("jwt")
                )
                if token:
                    prefix = auth.prefix or "Bearer"
                    return {auth.header: f"{prefix} {token}"}
        except (httpx.RequestError, ValueError):
            pass

    return {}


# ── Punto de entrada ──────────────────────────────────────────────────────────

def mutate(
    endpoint: Endpoint,
    findings: list[Finding],
    base_url: str,
    timeout: int = 5,
    auth: Optional[AuthConfig] = None,
) -> list[DastResult]:
    results = []
    url = f"{base_url}{endpoint.path}"

    with httpx.Client(timeout=timeout, verify=False) as client:
        # Resolver cabeceras de auth una sola vez por sesión
        auth_headers = _resolve_auth_headers(auth, client)

        for finding in findings:
            rule_results = _run_rule(
                client=client,
                url=url,
                endpoint=endpoint,
                finding=finding,
                auth_headers=auth_headers,
            )
            results.extend(rule_results)

    return results


# ── Dispatcher por regla ──────────────────────────────────────────────────────

def _run_rule(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    if finding.rule_id == "SAST-001":
        return _test_sql_injection(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-002":
        return _test_missing_auth(client, url, endpoint, finding)
    if finding.rule_id == "SAST-003":
        return _test_input_validation(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-004":
        return _test_secret_disclosure(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-005":
        return _test_exception_disclosure(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-006":
        return _test_bola(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-007":
        return _test_resource_consumption(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-008":
        return _test_function_level_auth(client, url, endpoint, finding)
    if finding.rule_id == "SAST-009":
        return _test_ssrf(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-010":
        return []  # Inventory: ya confirmado por SAST (ruta expuesta)
    return []


# ── DAST-001: SQL Injection ───────────────────────────────────────────────────

def _test_sql_injection(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    results = []

    for payload_value in SQL_PAYLOADS:
        body = (
            {arg: payload_value for arg in endpoint.args}
            if endpoint.args
            else {"q": payload_value}
        )
        # Sobreescribir con payload SQL sobre body inteligente
        smart = _build_smart_body(endpoint)
        body = {k: payload_value for k in smart} if smart else body

        try:
            response = _send(client, endpoint.method, url, body, headers=auth_headers)
            status = _evaluate_sql_response(response)
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload=body,
                    status_code=response.status_code,
                    response_snippet=response.text[:200],
                )
            )
            if status == Status.CONFIRMED:
                break
        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload=body,
                    error=str(e),
                )
            )
            break

    return results


def _evaluate_sql_response(response: httpx.Response) -> Status:
    error_indicators = (
        "sql", "syntax", "mysql", "postgresql", "sqlite",
        "ora-", "unclosed", "unterminated", "unexpected token",
    )
    body_lower = response.text.lower()

    if response.status_code == 500:
        if any(ind in body_lower for ind in error_indicators):
            return Status.CONFIRMED
        return Status.POTENTIAL

    if response.status_code == 200:
        if any(ind in body_lower for ind in error_indicators):
            return Status.CONFIRMED

    return Status.NOT_FOUND


# ── DAST-002: Autenticación ausente ──────────────────────────────────────────

def _test_missing_auth(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
) -> list[DastResult]:
    results = []

    for headers in AUTH_BYPASS_PAYLOADS:
        body = _build_smart_body(endpoint)

        try:
            response = _send(client, endpoint.method, url, body, headers=headers)
            status = _evaluate_auth_response(response)
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload={"headers": headers, "body": body},
                    status_code=response.status_code,
                    response_snippet=response.text[:200],
                )
            )
            if status == Status.CONFIRMED:
                break
        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload={"headers": headers},
                    error=str(e),
                )
            )
            break

    return results


def _evaluate_auth_response(response: httpx.Response) -> Status:
    if response.status_code in (200, 201):
        return Status.CONFIRMED
    if response.status_code in (401, 403):
        return Status.NOT_FOUND
    if response.status_code == 422:
        # 422 = FastAPI validó el body sin pedir token → auth ausente confirmada
        return Status.CONFIRMED
    if response.status_code == 500:
        # 500 = el endpoint ejecutó lógica de negocio sin pedir token → auth ausente confirmada
        return Status.CONFIRMED
    return Status.NOT_FOUND


# ── DAST-003: Validación de entrada ──────────────────────────────────────────

def _test_input_validation(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    results = []

    for payload_value in FUZZING_PAYLOADS[:4]:
        smart = _build_smart_body(endpoint)
        body = {k: payload_value for k in smart} if smart else {"data": payload_value}

        try:
            response = _send(client, endpoint.method, url, body, headers=auth_headers)
            status = _evaluate_validation_response(response)
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload=body,
                    status_code=response.status_code,
                    response_snippet=response.text[:200],
                )
            )
        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload=body,
                    error=str(e),
                )
            )
            break

    return results


def _evaluate_validation_response(response: httpx.Response) -> Status:
    if response.status_code == 500:
        return Status.CONFIRMED
    if response.status_code == 200:
        return Status.POTENTIAL
    if response.status_code == 422:
        return Status.NOT_FOUND
    return Status.NOT_FOUND


# ── DAST-006: BOLA ───────────────────────────────────────────────────────────

def _test_bola(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    """
    Intenta acceder a recursos con IDs distintos al del usuario autenticado.
    Un 200 con contenido distinto al propio indica BOLA confirmado.
    """
    results = []
    import re

    id_pattern = re.compile(r"\{(\w+)\}")
    path_params = id_pattern.findall(endpoint.path)
    if not path_params:
        return []

    for test_id in BOLA_ID_PAYLOADS[:3]:
        # Sustituir todos los parámetros de ruta con el ID de prueba
        test_url = url
        for param in path_params:
            test_url = re.sub(r"\{" + param + r"\}", str(test_id), test_url)

        try:
            response = _send(
                client, endpoint.method, test_url,
                body={}, headers=auth_headers
            )
            # 200 accediendo a un ID ajeno = BOLA confirmado
            if response.status_code == 200:
                status = Status.CONFIRMED
            elif response.status_code in (403, 404):
                status = Status.NOT_FOUND
            else:
                status = Status.POTENTIAL

            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload={"path_id": test_id, "url": test_url},
                    status_code=response.status_code,
                    response_snippet=response.text[:200],
                )
            )
            if status == Status.CONFIRMED:
                break
        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload={"path_id": test_id},
                    error=str(e),
                )
            )
            break

    return results


# ── DAST-007: Resource Consumption ───────────────────────────────────────────

def _test_resource_consumption(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    """
    Envía valores extremos en parámetros de paginación.
    Un 200 con respuesta masiva o un 500 indican consumo sin límite.
    """
    results = []

    for payload in RESOURCE_PAYLOADS:
        body = {**payload, **{arg: "test" for arg in endpoint.args if arg not in payload}}

        try:
            response = _send(client, endpoint.method, url, body, headers=auth_headers)

            if response.status_code == 200:
                # Respuesta muy grande puede indicar que no hay límite
                content_length = len(response.content)
                if content_length > 50_000:
                    status = Status.CONFIRMED
                else:
                    status = Status.POTENTIAL
            elif response.status_code == 500:
                status = Status.CONFIRMED
            elif response.status_code == 422:
                status = Status.NOT_FOUND  # Pydantic rechazó el valor
            else:
                status = Status.POTENTIAL

            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload=payload,
                    status_code=response.status_code,
                    response_snippet=f"response size: {len(response.content)} bytes | {response.text[:150]}",
                )
            )
            if status == Status.CONFIRMED:
                break
        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload=payload,
                    error=str(e),
                )
            )
            break

    return results


# ── DAST-008: Function Level Authorization ────────────────────────────────────

def _test_function_level_auth(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
) -> list[DastResult]:
    """
    Intenta acceder al endpoint administrativo sin credenciales o con token no privilegiado.
    Un 200/201 sin auth indica que el control de acceso falla.
    """
    results = []
    low_priv_headers = [
        {},
        {"Authorization": "Bearer invalid_token"},
        {"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."},  # JWT alg:none
    ]

    for headers in low_priv_headers:
        body = {arg: "test" for arg in endpoint.args} if endpoint.args else {}

        try:
            response = _send(client, endpoint.method, url, body, headers=headers)

            if response.status_code in (200, 201):
                status = Status.CONFIRMED
            elif response.status_code in (401, 403):
                status = Status.NOT_FOUND
            else:
                status = Status.POTENTIAL

            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload={"headers": headers},
                    status_code=response.status_code,
                    response_snippet=response.text[:200],
                )
            )
            if status == Status.CONFIRMED:
                break
        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload={"headers": headers},
                    error=str(e),
                )
            )
            break

    return results


# ── DAST-009: SSRF ────────────────────────────────────────────────────────────

def _test_ssrf(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    """
    Inyecta URLs de destinos internos/metadata cloud en parámetros de URL.
    Un 200 con contenido de metadata indica SSRF confirmado.
    """
    results = []

    for ssrf_url in SSRF_PAYLOADS:
        body = (
            {arg: ssrf_url for arg in endpoint.args}
            if endpoint.args
            else {"url": ssrf_url, "target": ssrf_url, "endpoint": ssrf_url}
        )

        try:
            response = _send(client, endpoint.method, url, body, headers=auth_headers)
            status = _evaluate_ssrf_response(response, ssrf_url)

            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload={"ssrf_url": ssrf_url},
                    status_code=response.status_code,
                    response_snippet=response.text[:200],
                )
            )
            if status == Status.CONFIRMED:
                break
        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload={"ssrf_url": ssrf_url},
                    error=str(e),
                )
            )

    return results


def _evaluate_ssrf_response(response: httpx.Response, ssrf_url: str) -> Status:
    body_lower = response.text.lower()

    # Indicadores de respuesta de metadata cloud
    cloud_metadata_indicators = (
        "ami-id", "instance-id", "computemetadata",
        "root:x:0", "daemon:", "/bin/bash",  # /etc/passwd
    )

    if response.status_code == 200:
        if any(ind in body_lower for ind in cloud_metadata_indicators):
            return Status.CONFIRMED
        # Respuesta exitosa a una URL interna es sospechosa
        if "169.254" in ssrf_url or "127.0.0.1" in ssrf_url or "metadata" in ssrf_url:
            return Status.POTENTIAL

    if response.status_code == 500:
        # Timeout o error de conexión interna puede indicar que se intentó la conexión
        return Status.POTENTIAL

    return Status.NOT_FOUND


# ── DAST-004: Secret Disclosure ──────────────────────────────────────────────

def _test_secret_disclosure(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    """
    Hace un request normal al endpoint y comprueba si el valor del secret
    hardcodeado aparece en la respuesta (information disclosure).
    También verifica si la respuesta expone campos sensibles en el body.
    """
    sensitive_keys = (
        "secret", "password", "passwd", "token", "api_key",
        "apikey", "private_key", "credentials", "auth",
    )

    body = {arg: "test" for arg in endpoint.args} if endpoint.args else {}

    try:
        response = _send(client, endpoint.method, url, body, headers=auth_headers)
        body_lower = response.text.lower()

        # Verificar si la respuesta contiene campos sensibles con valores reales
        exposed_fields = [k for k in sensitive_keys if f'"{k}"' in body_lower]

        if response.status_code == 200 and exposed_fields:
            status = Status.CONFIRMED
            evidence = f"Campos sensibles en respuesta: {', '.join(exposed_fields)}"
        elif response.status_code == 200:
            # El endpoint responde pero no expone el secret directamente
            # El finding SAST ya es suficiente evidencia
            status = Status.POTENTIAL
            evidence = "Endpoint accesible; secret detectado en código fuente"
        else:
            status = Status.POTENTIAL
            evidence = f"HTTP {response.status_code}"

        return [
            DastResult(
                endpoint=endpoint,
                finding=finding,
                status=status,
                payload=body,
                status_code=response.status_code,
                response_snippet=evidence,
            )
        ]

    except httpx.RequestError as e:
        return [
            DastResult(
                endpoint=endpoint,
                finding=finding,
                status=Status.POTENTIAL,
                payload=body,
                error=str(e),
            )
        ]


# ── DAST-005: Exception / Stack Trace Disclosure ──────────────────────────────

EXCEPTION_PAYLOADS = [
    None,
    "",
    "null",
    0,
    -99999,
    "A" * 10000,
    {"nested": {"deep": [1, 2, 3]}},
    "\x00\x01\x02",
    "'; SELECT 1--",
]

STACKTRACE_INDICATORS = (
    "traceback",
    "file \"",
    "line ",
    "exception",
    "error at",
    "syntaxerror",
    "typeerror",
    "valueerror",
    "keyerror",
    "attributeerror",
    "runtimeerror",
    "raise ",
    "def ",
    ".py\",",
    "sqlalchemy",
    "pydantic",
    "internal server error",
)


def _test_exception_disclosure(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    """
    Envía inputs que provocan excepciones y verifica si la respuesta
    filtra stack traces o mensajes de error internos del servidor.
    """
    results = []

    for payload_value in EXCEPTION_PAYLOADS[:5]:
        smart = _build_smart_body(endpoint)
        body = {k: payload_value for k in smart} if smart else {"data": payload_value}

        try:
            response = _send(client, endpoint.method, url, body, headers=auth_headers)
            body_lower = response.text.lower()

            if response.status_code == 500:
                matched = [ind for ind in STACKTRACE_INDICATORS if ind in body_lower]
                if matched:
                    status = Status.CONFIRMED
                    snippet = f"Stack trace expuesto: '{matched[0]}' detectado en respuesta"
                else:
                    status = Status.POTENTIAL
                    snippet = "HTTP 500 sin stack trace visible"
            elif response.status_code == 200:
                matched = [ind for ind in STACKTRACE_INDICATORS if ind in body_lower]
                if matched:
                    status = Status.CONFIRMED
                    snippet = f"Información interna en respuesta 200: '{matched[0]}'"
                else:
                    status = Status.NOT_FOUND
                    snippet = "HTTP 200 sin información sensible"
            else:
                status = Status.NOT_FOUND
                snippet = f"HTTP {response.status_code}"

            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=status,
                    payload=body,
                    status_code=response.status_code,
                    response_snippet=snippet,
                )
            )

            if status == Status.CONFIRMED:
                break

        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.NOT_FOUND,
                    payload=body,
                    error=str(e),
                )
            )
            break

    return results


# ── Smart body builder ────────────────────────────────────────────────────────

def _build_smart_body(endpoint: Endpoint, fallback_value: Any = "test") -> dict[str, Any]:
    body: dict[str, Any] = {}

    if not endpoint.arg_infos:
        return {arg: fallback_value for arg in endpoint.args}

    for arg_info in endpoint.arg_infos:
        if arg_info.is_pydantic and arg_info.source_file is not None:
            pydantic_body = build_body(
                arg_info.annotation,
                arg_info.source_file,
                enum_map=endpoint.enum_map,
            )
            if pydantic_body is not None:
                body.update(pydantic_body)
                continue

        body[arg_info.name] = fallback_value

    return body


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _send(
    client: httpx.Client,
    method: str,
    url: str,
    body: dict,
    headers: Optional[dict] = None,
) -> httpx.Response:
    default_headers = {"Content-Type": "application/json"}
    if headers:
        default_headers.update(headers)

    method = method.upper()

    if method == "GET":
        return client.get(url, params=body, headers=default_headers)
    if method == "POST":
        return client.post(url, json=body, headers=default_headers)
    if method == "PUT":
        return client.put(url, json=body, headers=default_headers)
    if method == "PATCH":
        return client.patch(url, json=body, headers=default_headers)
    if method == "DELETE":
        return client.delete(url, headers=default_headers)

    return client.request(method, url, json=body, headers=default_headers)

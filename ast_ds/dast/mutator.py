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
    NOT_CONFIRMED = "NO CONFIRMADO"
    INCONCLUSIVE = "INCONCLUSIVO"
    POTENTIAL = "POTENCIAL"


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
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22",
    "http://127.0.0.1:6379",
    "http://192.168.1.1",
    "file:///etc/passwd",
    "http://0.0.0.0:80",
]

BOLA_ID_PAYLOADS = [
    "1", "2", "0", "-1", "99999999",
    "00000000-0000-0000-0000-000000000001",
]


# ── Resolución de token de autenticación ──────────────────────────────────────

def _resolve_auth_headers(
    auth: Optional[AuthConfig],
    client: httpx.Client,
) -> dict[str, str]:
    if auth is None:
        return {}

    auth_type = auth.type.lower()

    if auth.token:
        prefix = auth.prefix or "Bearer"
        return {auth.header: f"{prefix} {auth.token}"}

    if auth_type == "apikey" and auth.api_key:
        return {auth.header: auth.api_key}

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

def _resolve_path_params(path: str, id_value: str = "1") -> str:
    """
    Sustituye los path params con valores de prueba válidos.
    ej: /orders/{order_id}/vulnerable → /orders/1/vulnerable
    id_value permite probar distintos IDs para BOLA.
    """
    import re
    def replace_param(match):
        param_name = match.group(1).lower()
        if "id" in param_name:
            return id_value
        if "uuid" in param_name:
            return f"00000000-0000-0000-0000-00000000000{id_value}"
        if "name" in param_name:
            return "test"
        if "slug" in param_name:
            return "test-item"
        return id_value
    return re.sub(r"\{(\w+)\}", replace_param, path)


def mutate(
    endpoint: Endpoint,
    findings: list[Finding],
    base_url: str,
    timeout: int = 5,
    auth: Optional[AuthConfig] = None,
) -> list[DastResult]:
    results = []
    url = f"{base_url}{_resolve_path_params(endpoint.path)}"

    with httpx.Client(timeout=timeout, verify=False) as client:
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
        return []  # Inventory: validacion estatica unicamente
    if finding.rule_id == "SAST-011":
        return _test_sensitive_business_flow(client, url, endpoint, finding, auth_headers)
    if finding.rule_id == "SAST-012":
        return []  # Unsafe API consumption: validacion estatica unicamente
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
        smart = _build_smart_body(endpoint)
        body = {k: payload_value for k in smart} if smart else {"q": payload_value}

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
                    status=Status.INCONCLUSIVE,
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
        return Status.INCONCLUSIVE

    if response.status_code == 200:
        if any(ind in body_lower for ind in error_indicators):
            return Status.CONFIRMED

    return Status.NOT_CONFIRMED


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
                    status=Status.INCONCLUSIVE,
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
        return Status.NOT_CONFIRMED
    if response.status_code == 422:
        # 422 indica validacion de datos, no ausencia de autenticacion confirmada
        return Status.INCONCLUSIVE
    if response.status_code == 500:
        # 500 no demuestra ejecucion no autorizada por si solo
        return Status.INCONCLUSIVE
    return Status.INCONCLUSIVE


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
                    status=Status.INCONCLUSIVE,
                    payload=body,
                    error=str(e),
                )
            )
            break

    return results


def _evaluate_validation_response(response: httpx.Response) -> Status:
    if response.status_code == 500:
        # 500 solo no demuestra modificacion o acceso indebido
        return Status.INCONCLUSIVE
    if response.status_code == 200:
        return Status.POTENTIAL
    if response.status_code == 422:
        return Status.NOT_CONFIRMED
    return Status.INCONCLUSIVE


# ── DAST-006: BOLA ───────────────────────────────────────────────────────────

def _test_bola(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    results = []
    import re

    id_pattern = re.compile(r"\{(\w+)\}")
    path_params = id_pattern.findall(endpoint.path)
    if not path_params:
        return []

    for test_id in BOLA_ID_PAYLOADS:
        test_url = url
        for param in path_params:
            test_url = re.sub(r"\{" + param + r"\}", str(test_id), test_url)

        try:
            response = _send(
                client, endpoint.method, test_url,
                body={}, headers=auth_headers
            )
            if response.status_code == 200:
                status = Status.CONFIRMED
            elif response.status_code in (403, 404):
                status = Status.NOT_CONFIRMED
            else:
                status = Status.INCONCLUSIVE

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
                    status=Status.INCONCLUSIVE,
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
    results = []

    for payload in RESOURCE_PAYLOADS:
        # Construir body inteligente y sustituir campos de paginación
        smart = _build_smart_body(endpoint)
        if smart:
            # Sustituir campos de paginación en el body inteligente
            body = {**smart}
            for k in list(body.keys()):
                if k.lower() in {p.lower() for p in RESOURCE_PAYLOADS[0].keys()}:
                    body[k] = list(payload.values())[0]
            # Si no hay campo de paginación en el modelo, añadir directamente
            if not any(k.lower() in {"limit", "page_size", "count", "size", "per_page"} for k in smart):
                body = {**payload}
        else:
            body = {**payload, **{arg: "test" for arg in endpoint.args if arg not in payload}}

        try:
            response = _send(client, endpoint.method, url, body, headers=auth_headers)

            if response.status_code == 200:
                content_length = len(response.content)
                # Confirmar si respuesta es grande O si devuelve muchos items JSON
                if content_length > 50_000:
                    status = Status.CONFIRMED
                else:
                    # Verificar si la respuesta JSON tiene muchos items
                    try:
                        json_body = response.json()
                        if isinstance(json_body, list) and len(json_body) > 100:
                            status = Status.CONFIRMED
                        elif isinstance(json_body, dict):
                            for v in json_body.values():
                                if isinstance(v, list) and len(v) > 100:
                                    status = Status.CONFIRMED
                                    break
                            else:
                                status = Status.POTENTIAL
                        else:
                            status = Status.POTENTIAL
                    except Exception:
                        status = Status.POTENTIAL
            elif response.status_code == 500:
                # 500 no demuestra consumo no restringido por si solo
                status = Status.INCONCLUSIVE
            elif response.status_code == 422:
                status = Status.NOT_CONFIRMED
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
                    status=Status.INCONCLUSIVE,
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
    results = []
    low_priv_headers = [
        {},
        {"Authorization": "Bearer invalid_token"},
        {"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."},
    ]

    for headers in low_priv_headers:
        body = {arg: "test" for arg in endpoint.args} if endpoint.args else {}

        try:
            response = _send(client, endpoint.method, url, body, headers=headers)

            if response.status_code in (200, 201):
                status = Status.CONFIRMED
            elif response.status_code in (401, 403):
                status = Status.NOT_CONFIRMED
            else:
                status = Status.INCONCLUSIVE

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
                    status=Status.INCONCLUSIVE,
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
    results = []

    for ssrf_url in SSRF_PAYLOADS:
        # Construir body inteligente y sustituir campos de URL con el payload SSRF
        smart = _build_smart_body(endpoint)
        if smart:
            # Sustituir campos que parecen URLs o destinos
            url_field_names = {"url", "target", "endpoint", "uri", "href", "link", "destination", "host"}
            body = {}
            for k, v in smart.items():
                if k.lower() in url_field_names or "url" in k.lower():
                    body[k] = ssrf_url
                else:
                    body[k] = v
            # Si no hay campo de URL, usar fallback
            if not any(k.lower() in url_field_names or "url" in k.lower() for k in smart):
                body = {"url": ssrf_url, "target": ssrf_url}
        else:
            body = {"url": ssrf_url, "target": ssrf_url, "endpoint": ssrf_url}

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
                    status=Status.INCONCLUSIVE,
                    payload={"ssrf_url": ssrf_url},
                    error=str(e),
                )
            )

    return results


def _evaluate_ssrf_response(response: httpx.Response, ssrf_url: str) -> Status:
    body_lower = response.text.lower()

    cloud_metadata_indicators = (
        "ami-id", "instance-id", "computemetadata",
        "root:x:0", "daemon:", "/bin/bash",
    )

    if response.status_code == 200:
        if any(ind in body_lower for ind in cloud_metadata_indicators):
            return Status.CONFIRMED
        if "169.254" in ssrf_url or "127.0.0.1" in ssrf_url or "metadata" in ssrf_url:
            return Status.POTENTIAL

    if response.status_code == 500:
        return Status.INCONCLUSIVE

    return Status.NOT_CONFIRMED


# ── DAST-004: Secret Disclosure ──────────────────────────────────────────────

def _test_secret_disclosure(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    sensitive_keys = (
        "secret", "password", "passwd", "token", "api_key",
        "apikey", "private_key", "credentials", "auth",
    )

    body = {arg: "test" for arg in endpoint.args} if endpoint.args else {}

    try:
        response = _send(client, endpoint.method, url, body, headers=auth_headers)
        body_lower = response.text.lower()

        exposed_fields = [k for k in sensitive_keys if f'"{k}"' in body_lower]

        if response.status_code == 200 and exposed_fields:
            status = Status.CONFIRMED
            evidence = f"Campos sensibles en respuesta: {', '.join(exposed_fields)}"
        elif response.status_code == 200:
            status = Status.POTENTIAL
            evidence = "Endpoint accesible; secret detectado en codigo fuente"
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
                status=Status.INCONCLUSIVE,
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
                    status = Status.INCONCLUSIVE
                    snippet = "HTTP 500 sin stack trace visible"
            elif response.status_code == 200:
                matched = [ind for ind in STACKTRACE_INDICATORS if ind in body_lower]
                if matched:
                    status = Status.CONFIRMED
                    snippet = f"Informacion interna en respuesta 200: '{matched[0]}'"
                else:
                    status = Status.NOT_CONFIRMED
                    snippet = "HTTP 200 sin informacion sensible"
            else:
                status = Status.NOT_CONFIRMED
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
                    status=Status.INCONCLUSIVE,
                    payload=body,
                    error=str(e),
                )
            )
            break

    return results


# ── DAST-011: Sensitive Business Flow ────────────────────────────────────────

def _test_sensitive_business_flow(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
    auth_headers: dict[str, str],
) -> list[DastResult]:
    results = []
    body = _build_smart_body(endpoint)
    blocked = False

    for i in range(5):
        try:
            response = _send(client, endpoint.method, url, body, headers=auth_headers)

            if response.status_code == 429:
                blocked = True
                results.append(
                    DastResult(
                        endpoint=endpoint,
                        finding=finding,
                        status=Status.NOT_CONFIRMED,
                        payload={"attempt": i + 1},
                        status_code=response.status_code,
                        response_snippet="Rate limiting activo — 429 detectado",
                    )
                )
                break

        except httpx.RequestError as e:
            results.append(
                DastResult(
                    endpoint=endpoint,
                    finding=finding,
                    status=Status.INCONCLUSIVE,
                    payload={"attempt": i + 1},
                    error=str(e),
                )
            )
            break

    if not blocked:
        results.append(
            DastResult(
                endpoint=endpoint,
                finding=finding,
                status=Status.CONFIRMED,
                payload={"attempts": 5},
                status_code=None,
                response_snippet="5 solicitudes consecutivas aceptadas sin bloqueo (sin rate limiting)",
            )
        )

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
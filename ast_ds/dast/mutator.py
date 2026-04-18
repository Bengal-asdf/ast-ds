from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

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


# ── Payloads por tipo de vulnerabilidad ──────────────────────────────────────

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
]


# ── Punto de entrada ──────────────────────────────────────────────────────────


def mutate(
    endpoint: Endpoint,
    findings: list[Finding],
    base_url: str,
    timeout: int = 5,
) -> list[DastResult]:
    results = []
    url = f"{base_url}{endpoint.path}"

    with httpx.Client(timeout=timeout, verify=False) as client:
        for finding in findings:
            rule_results = _run_rule(
                client=client,
                url=url,
                endpoint=endpoint,
                finding=finding,
            )
            results.extend(rule_results)

    return results


# ── Dispatcher por regla ──────────────────────────────────────────────────────


def _run_rule(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
) -> list[DastResult]:
    if finding.rule_id == "SAST-001":
        return _test_sql_injection(client, url, endpoint, finding)
    if finding.rule_id == "SAST-002":
        return _test_missing_auth(client, url, endpoint, finding)
    if finding.rule_id == "SAST-003":
        return _test_input_validation(client, url, endpoint, finding)
    if finding.rule_id == "SAST-004":
        return []  # Secret hardcodeado: no requiere request, ya confirmado por SAST
    if finding.rule_id == "SAST-005":
        return []  # Manejo de excepciones: no requiere request
    return []


# ── DAST-001: SQL Injection ───────────────────────────────────────────────────


def _test_sql_injection(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
) -> list[DastResult]:
    results = []

    for payload_value in SQL_PAYLOADS:
        body = (
            {arg: payload_value for arg in endpoint.args}
            if endpoint.args
            else {"q": payload_value}
        )

        try:
            response = _send(client, endpoint.method, url, body)
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
        "sql",
        "syntax",
        "mysql",
        "postgresql",
        "sqlite",
        "ora-",
        "unclosed",
        "unterminated",
        "unexpected token",
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


# ── DAST-002: Autenticación ───────────────────────────────────────────────────


def _test_missing_auth(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
) -> list[DastResult]:
    results = []

    for headers in AUTH_BYPASS_PAYLOADS:
        body = {arg: "test" for arg in endpoint.args} if endpoint.args else {}

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
    if response.status_code in (200, 201, 422):
        return Status.CONFIRMED
    if response.status_code in (401, 403):
        return Status.NOT_FOUND
    if response.status_code == 422:
        return Status.POTENTIAL
    return Status.NOT_FOUND


# ── DAST-003: Validación de entrada ──────────────────────────────────────────


def _test_input_validation(
    client: httpx.Client,
    url: str,
    endpoint: Endpoint,
    finding: Finding,
) -> list[DastResult]:
    results = []

    for payload_value in FUZZING_PAYLOADS[:4]:
        body = (
            {arg: payload_value for arg in endpoint.args}
            if endpoint.args
            else {"data": payload_value}
        )

        try:
            response = _send(client, endpoint.method, url, body)
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

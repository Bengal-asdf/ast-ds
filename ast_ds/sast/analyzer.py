import ast
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from ..scanner import Endpoint


class Severity(str, Enum):
    CRITICAL = "CRÍTICO"
    HIGH     = "ALTO"
    MEDIUM   = "MEDIO"
    LOW      = "BAJO"


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

    return findings


# ── REGLA 1: SQL Injection ────────────────────────────────────────────────────
def _check_sql_injection(tree: ast.AST, source: str) -> list[Finding]:
    findings = []
    sql_keywords = ("select", "insert", "update", "delete", "from", "where")

    for node in ast.walk(tree):
        # Buscar concatenación de strings: "SELECT " + variable
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            node_source = ast.unparse(node).lower()
            if any(kw in node_source for kw in sql_keywords):
                findings.append(Finding(
                    rule_id="SAST-001",
                    title="Posible SQL Injection",
                    description="Se detectó concatenación de strings en lo que parece una query SQL.",
                    severity=Severity.CRITICAL,
                    lineno=node.lineno if hasattr(node, "lineno") else 0,
                    owasp="API8:2023 — Security Misconfiguration",
                    evidence=ast.unparse(node)[:120],
                ))

        # Buscar f-strings con SQL: f"SELECT * FROM {tabla}"
        if isinstance(node, ast.JoinedStr):
            node_source = ast.unparse(node).lower()
            if any(kw in node_source for kw in sql_keywords):
                findings.append(Finding(
                    rule_id="SAST-001",
                    title="Posible SQL Injection via f-string",
                    description="Se detectó un f-string que construye una query SQL con variables.",
                    severity=Severity.CRITICAL,
                    lineno=node.lineno if hasattr(node, "lineno") else 0,
                    owasp="API8:2023 — Security Misconfiguration",
                    evidence=ast.unparse(node)[:120],
                ))

    return findings


# ── REGLA 2: Ausencia de autenticación ───────────────────────────────────────
def _check_missing_auth(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    auth_keywords = (
        "current_user", "get_current_user", "verify_token",
        "oauth2_scheme", "security", "authorize", "token",
        "Depends", "HTTPBearer", "APIKeyHeader",
    )

    source_lower = (endpoint.source_code or "").lower()
    has_auth = any(kw.lower() in source_lower for kw in auth_keywords)

    # Solo alertar en endpoints que modifican datos
    if not has_auth and endpoint.method in ("POST", "PUT", "PATCH", "DELETE"):
        return [Finding(
            rule_id="SAST-002",
            title="Ausencia de control de autenticación",
            description=(
                f"El endpoint {endpoint.method} {endpoint.path} no presenta "
                "mecanismos de autenticación detectables."
            ),
            severity=Severity.HIGH,
            lineno=1,
            owasp="API2:2023 — Broken Authentication",
        )]

    return []


# ── REGLA 3: Ausencia de validación de entrada ────────────────────────────────
def _check_missing_input_validation(tree: ast.AST, endpoint: Endpoint) -> list[Finding]:
    findings = []
    pydantic_types = ("BaseModel", "Field", "validator", "model_validator")
    source = endpoint.source_code or ""

    has_pydantic = any(t in source for t in pydantic_types)

    # Buscar parámetros sin tipo definido
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for arg in node.args.args:
            if arg.arg in ("self", "request", "response", "db", "session"):
                continue
            if arg.annotation is None and not has_pydantic:
                findings.append(Finding(
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
                ))

    return findings


# ── REGLA 4: Secrets hardcodeados ────────────────────────────────────────────
def _check_hardcoded_secrets(tree: ast.AST) -> list[Finding]:
    findings = []
    secret_keywords = (
        "secret", "password", "passwd", "token", "api_key",
        "apikey", "auth", "private_key", "credentials",
    )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id.lower()
            if any(kw in var_name for kw in secret_keywords):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    if len(node.value.value) > 4:
                        findings.append(Finding(
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
                        ))

    return findings


# ── REGLA 5: Manejo amplio de excepciones ────────────────────────────────────
def _check_broad_exception(tree: ast.AST) -> list[Finding]:
    findings = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            findings.append(Finding(
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
            ))

    return findings
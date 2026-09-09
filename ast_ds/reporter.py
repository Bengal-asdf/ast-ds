from rich.console import Console
from rich.live import Live
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)
from rich.rule import Rule
from rich.text import Text

from .config import AuthConfig
from .dast.mutator import DastResult, Status
from .sast.analyzer import Finding, Severity
from .scanner import Endpoint

console = Console(highlight=False)

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange3",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "dim",
}

STATUS_COLORS = {
    Status.CONFIRMED: "red",
    Status.POTENTIAL: "yellow",
    Status.NOT_CONFIRMED: "green",
    Status.INCONCLUSIVE: "dim yellow",
}

STATUS_LABELS = {
    Status.CONFIRMED: "CONFIRMADO",
    Status.POTENTIAL: "POTENCIAL",
    Status.NOT_CONFIRMED: "NO CONFIRMADO",
    Status.INCONCLUSIVE: "INCONCLUSIVO",
}

_route_width = 50


def print_header():
    console.print()
    console.print(
        Text("ast-ds v0.2.0", style="bold white")
        + Text(" — Application Security Testing", style="dim")
    )
    console.print()


def print_scanning(total: int, endpoints: list[Endpoint] = []):
    global _route_width
    if endpoints:
        max_len = max(len(f"{ep.method} {ep.path}") for ep in endpoints)
        _route_width = max_len + 4

    console.print(
        Text("Detectando endpoints... ", style="dim")
        + Text(str(total), style="bold")
        + Text(" encontrados", style="dim")
    )
    console.print()


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="blue"),
        TextColumn("[bold]{task.description}"),
        BarColumn(
            bar_width=30,
            complete_style="blue",
            finished_style="green",
            pulse_style="dim blue",
        ),
        TextColumn("[dim]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def print_endpoint_progress(
    endpoint: Endpoint,
    findings: list[Finding],
    dast_results: list[DastResult],
    current: int,
    total: int,
    progress: Progress = None,
    task_id=None,
):
    if progress is None or task_id is None:
        return

    vuln_count = len(findings)
    method_color = _method_color(endpoint.method)
    route = f"{endpoint.method} {endpoint.path}"

    if vuln_count == 0:
        vuln_label = Text(" 0 vulnerabilidades", style="green")
    else:
        label = f" {vuln_count} vulnerabilidad{'es' if vuln_count > 1 else ''}"
        vuln_label = Text(label, style="red")

    desc = Text(f"{route:<{_route_width}}", style=method_color)
    desc.append_text(vuln_label)

    progress.update(
        task_id,
        description=desc.plain,
        completed=current,
    )


def print_summary(
    endpoints: list[Endpoint],
    all_findings: list[list[Finding]],
    all_dast: list[list[DastResult]],
):
    total_vulns = sum(len(f) for f in all_findings)
    total_confirmed = sum(
        1 for results in all_dast for r in results if r.status == Status.CONFIRMED
    )

    console.print()
    console.print(Rule(style="dim"))

    summary = Text()
    summary.append("Endpoints analizados: ", style="dim")
    summary.append(str(len(endpoints)), style="bold")
    summary.append("  |  Vulnerabilidades detectadas: ", style="dim")
    summary.append(str(total_vulns), style="bold")
    summary.append("  |  Confirmadas: ", style="dim")
    summary.append(str(total_confirmed), style="bold red")
    console.print(summary)

    if total_vulns == 0:
        console.print()
        console.print(Text("Sin vulnerabilidades detectadas.", style="bold green"))
        console.print(Rule(style="dim"))
        return

    console.print()

    for endpoint, findings, dast_results in zip(endpoints, all_findings, all_dast):
        if not findings:
            continue

        method_color = _method_color(endpoint.method)
        header = Text()
        header.append(f"  {endpoint.method}", style=f"bold {method_color}")
        header.append(f" {endpoint.path}", style="bold white")
        console.print(header)

        dast_map = {r.finding.rule_id: r for r in dast_results}

        for finding in findings:
            sev_color = SEVERITY_COLORS[finding.severity]
            dast = dast_map.get(finding.rule_id)

            line = Text()
            line.append(f"    [{finding.severity.value}]", style=sev_color)
            line.append(f" {finding.title}", style="white")

            if dast:
                status_color = STATUS_COLORS[dast.status]
                label = STATUS_LABELS[dast.status]
                line.append(f"  → {label}", style=status_color)

            console.print(line)

            if finding.evidence:
                console.print(
                    Text("      evidencia: ", style="dim")
                    + Text(finding.evidence[:80], style="italic dim")
                )

            console.print(Text(f"      OWASP: {finding.owasp}", style="dim"))

    console.print(Rule(style="dim"))


def print_error(message: str):
    console.print()
    console.print(Text("Error: ", style="bold red") + Text(message, style="white"))
    console.print()


def print_auth_info(auth: AuthConfig):
    auth_type = auth.type.upper()
    if auth.token:
        source = "token estático"
    elif auth.login_url:
        source = f"login dinámico → {auth.login_url}"
    elif auth.api_key:
        source = "API key"
    else:
        source = "sin credenciales configuradas"

    console.print(
        Text("Autenticación: ", style="dim")
        + Text(auth_type, style="bold cyan")
        + Text(f" ({source})", style="dim")
    )
    console.print()


def print_no_endpoints():
    console.print()
    console.print(
        Text("No se encontraron endpoints FastAPI en el target.", style="yellow")
    )
    console.print(
        Text(
            "Verifica que el archivo contiene rutas decoradas con @router o @app.",
            style="dim",
        )
    )
    console.print()


def _method_color(method: str) -> str:
    colors = {
        "GET": "green",
        "POST": "blue",
        "PUT": "yellow",
        "PATCH": "yellow",
        "DELETE": "red",
    }
    return colors.get(method.upper(), "white")
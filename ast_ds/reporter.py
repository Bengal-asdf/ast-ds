from rich.console import Console
from rich.text import Text
from rich.rule import Rule
from .scanner import Endpoint
from .sast.analyzer import Finding, Severity
from .dast.mutator import DastResult, Status

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH:     "orange3",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "dim",
}

STATUS_COLORS = {
    Status.CONFIRMED:  "red",
    Status.POTENTIAL:  "yellow",
    Status.NOT_FOUND:  "green",
}

STATUS_LABELS = {
    Status.CONFIRMED: "CONFIRMADO",
    Status.POTENTIAL: "POTENCIAL",
    Status.NOT_FOUND: "NO DETECTADO",
}


def print_header():
    console.print()
    console.print(Text("ast-ds v0.1.0", style="bold white"), "—",
                  Text("Application Security Testing", style="dim"))
    console.print()


def print_scanning(total: int):
    console.print(f"[dim]Detectando endpoints...[/dim] "
                  f"[bold]{total}[/bold] encontrados\n")
    console.print("[dim]Analizando endpoints...[/dim]")


def print_endpoint_progress(
    endpoint: Endpoint,
    findings: list[Finding],
    dast_results: list[DastResult],
    current: int,
    total: int,
):
    percent = int((current / total) * 100)
    bar = _progress_bar(current, total)

    vuln_count = len(findings)
    confirmed = sum(1 for r in dast_results if r.status == Status.CONFIRMED)

    if vuln_count == 0:
        vuln_text = Text("0 vulnerabilidades", style="green")
    else:
        label = f"{vuln_count} vulnerabilidad{'es' if vuln_count > 1 else ''}"
        if confirmed > 0:
            label += f" ({confirmed} confirmada{'s' if confirmed > 1 else ''})"
        vuln_text = Text(label, style="red")

    method_style = _method_color(endpoint.method)
    route = f"{endpoint.method} {endpoint.path}"

    line = Text()
    line.append(f"{route:<40}", style=method_style)
    line.append(" ")
    line.append(vuln_text)
    line.append(f" {bar} {percent}%", style="dim")

    console.print(line)


def print_summary(
    endpoints: list[Endpoint],
    all_findings: list[list[Finding]],
    all_dast: list[list[DastResult]],
):
    total_vulns = sum(len(f) for f in all_findings)
    total_confirmed = sum(
        1 for results in all_dast
        for r in results if r.status == Status.CONFIRMED
    )

    console.print()
    console.print(Rule(style="dim"))

    console.print(
        f"Endpoints analizados: [bold]{len(endpoints)}[/bold]  |  "
        f"Vulnerabilidades detectadas: [bold]{total_vulns}[/bold]  |  "
        f"Confirmadas: [bold red]{total_confirmed}[/bold red]"
    )

    if total_vulns == 0:
        console.print("\n[green bold]Sin vulnerabilidades detectadas.[/green bold]")
        console.print(Rule(style="dim"))
        return

    console.print()

    for endpoint, findings, dast_results in zip(endpoints, all_findings, all_dast):
        if not findings:
            continue

        method_style = _method_color(endpoint.method)
        console.print(
            Text(f"  {endpoint.method}", style=f"bold {method_style}"),
            Text(f" {endpoint.path}", style="bold"),
        )

        dast_map = {r.finding.rule_id: r for r in dast_results}

        for finding in findings:
            sev_color = SEVERITY_COLORS[finding.severity]
            dast = dast_map.get(finding.rule_id)

            line = Text()
            line.append(f"    [{finding.severity.value}]", style=f"bold {sev_color}")
            line.append(f" {finding.title}", style="white")

            if dast:
                status_color = STATUS_COLORS[dast.status]
                label = STATUS_LABELS[dast.status]
                line.append(f"  → {label}", style=status_color)

            console.print(line)

            if finding.evidence:
                console.print(
                    f"      [dim]evidencia:[/dim] [italic dim]{finding.evidence[:80]}[/italic dim]"
                )

            console.print(
                f"      [dim]OWASP: {finding.owasp}[/dim]"
            )

    console.print(Rule(style="dim"))


def print_error(message: str):
    console.print(f"\n[bold red]Error:[/bold red] {message}\n")


def print_no_endpoints():
    console.print("\n[yellow]No se encontraron endpoints FastAPI en el target.[/yellow]")
    console.print("[dim]Verifica que el archivo o carpeta contiene rutas decoradas con @router o @app.[/dim]\n")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _progress_bar(current: int, total: int, width: int = 8) -> str:
    filled = int((current / total) * width)
    empty = width - filled
    return f"[green]{'█' * filled}[/green][dim]{'░' * empty}[/dim]"


def _method_color(method: str) -> str:
    colors = {
        "GET":    "green",
        "POST":   "blue",
        "PUT":    "yellow",
        "PATCH":  "yellow",
        "DELETE": "red",
    }
    return colors.get(method.upper(), "white")
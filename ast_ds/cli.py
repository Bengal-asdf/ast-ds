import time

import click

from . import config as cfg
from . import reporter, scanner
from .dast import mutator
from .sast import analyzer


@click.group()
def app():
    """ast-ds — Application Security Testing Dynamic Static para endpoints FastAPI."""
    pass


@app.command("run")
@click.option(
    "--timeout",
    default=5,
    show_default=True,
    help="Timeout en segundos para cada request DAST.",
)
def run(timeout: int):
    """Analiza los endpoints FastAPI definidos en config.yaml."""

    reporter.print_header()

    # ── 1. Cargar configuración ───────────────────────────────────────────────
    try:
        config = cfg.load_config()
    except (FileNotFoundError, ValueError) as e:
        reporter.print_error(str(e))
        raise SystemExit(1)

    # ── 2. Detectar endpoints ─────────────────────────────────────────────────
    endpoints = scanner.scan(config)

    if config.prefix:
        for ep in endpoints:
            if not ep.path.startswith(config.prefix):
                ep.path = config.prefix + ep.path

    if not endpoints:
        reporter.print_no_endpoints()
        raise SystemExit(0)

    reporter.print_scanning(len(endpoints), endpoints)

    # ── 3. Analizar con una tarea por endpoint ────────────────────────────────
    all_findings: list = []
    all_dast: list = []

    progress = reporter.make_progress()

    with progress:
        for index, endpoint in enumerate(endpoints, start=1):
            route = f"{endpoint.method} {endpoint.path}"
            rw = reporter._route_width

            # Crear tarea para este endpoint
            task_id = progress.add_task(
                description=f"{route:<{rw}}[dim]analizando...[/dim]",
                total=1,
            )

            # Delay mínimo para que el spinner sea visible
            time.sleep(0.4)

            # SAST
            findings = analyzer.analyze(endpoint)

            # DAST
            if findings:
                dast_results = mutator.mutate(
                    endpoint=endpoint,
                    findings=findings,
                    base_url=config.base_url,
                    timeout=timeout,
                )
            else:
                dast_results = []

            all_findings.append(findings)
            all_dast.append(dast_results)

            # Resultado final del endpoint
            vuln_count = len(findings)
            if vuln_count == 0:
                result = f"[green]{'0 vulnerabilidades':<22}[/green]"
            else:
                label = f"{vuln_count} vulnerabilidad{'es' if vuln_count > 1 else ''}"
                result = f"[red]{label:<22}[/red]"

            method_color = reporter._method_color(endpoint.method)
            progress.update(
                task_id,
                description=f"[{method_color}]{route:<{rw}}[/{method_color}]{result}",
                completed=1,
            )

    # ── 4. Mostrar resumen final ──────────────────────────────────────────────
    reporter.print_summary(
        endpoints=endpoints,
        all_findings=all_findings,
        all_dast=all_dast,
    )

import click
from . import config as cfg
from . import scanner
from . import reporter
from .sast import analyzer
from .dast import mutator


@click.group()
def app():
    """ast-ds — Application Security Testing Dynamic Static para endpoints FastAPI."""
    pass


@app.command("run")
def run():
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

    if not endpoints:
        reporter.print_no_endpoints()
        raise SystemExit(0)

    reporter.print_scanning(len(endpoints))

    # ── 3. Analizar cada endpoint ─────────────────────────────────────────────
    all_findings: list = []
    all_dast: list = []

    for index, endpoint in enumerate(endpoints, start=1):

        findings = analyzer.analyze(endpoint)

        if findings:
            dast_results = mutator.mutate(
                endpoint=endpoint,
                findings=findings,
                base_url=config.base_url,
            )
        else:
            dast_results = []

        all_findings.append(findings)
        all_dast.append(dast_results)

        reporter.print_endpoint_progress(
            endpoint=endpoint,
            findings=findings,
            dast_results=dast_results,
            current=index,
            total=len(endpoints),
        )

    # ── 4. Mostrar resumen final ──────────────────────────────────────────────
    reporter.print_summary(
        endpoints=endpoints,
        all_findings=all_findings,
        all_dast=all_dast,
    )
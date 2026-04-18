# ast-ds

**Application Security Testing — Dynamic Static**

Herramienta Python instalable que integra análisis estático (SAST) y dinámico (DAST) de seguridad para endpoints de aplicaciones FastAPI, al estilo de herramientas como `pytest` o `mutmut`.

---

## Requisitos

- Python 3.11 o superior
- pip
- git

---

## Instalación

### En modo desarrollo (repositorio local)

```bash
git clone https://github.com/Bengal-asdf/ast-ds
cd ast-ds
pip install -e .
```

### En un proyecto FastAPI externo

Si tienes tu propio proyecto FastAPI y quieres analizar sus endpoints:

```bash
# 1. Clonar ast-ds en tu máquina
git clone https://github.com/Bengal-asdf/ast-ds

# 2. Ir a tu proyecto FastAPI
cd ~/tu-proyecto-fastapi

# 3. Activar tu entorno virtual
source .venv/bin/activate

# 4. Instalar ast-ds apuntando a la carpeta clonada
pip install -e ~/ruta/donde/clonaste/ast-ds

# 5. Verificar instalación
ast-ds --help
```

> El flag `-e` instala en modo editable — si ast-ds se actualiza con `git pull`,
> los cambios se reflejan automáticamente sin reinstalar.

### Actualizar ast-ds

```bash
# Ir a la carpeta donde clonaste ast-ds
cd ~/ruta/donde/clonaste/ast-ds

# Obtener últimos cambios
git pull

# Los cambios ya están activos en todos los proyectos que lo usan
```

---

## Configuración

Crea un archivo `config.yaml` en la raíz de tu proyecto FastAPI:

```yaml
# Analizar un archivo específico
target: app/api/router/oauth/oauth.py
base_url: http://localhost:8000

# Analizar una carpeta completa
# target: app/api/router/*
# base_url: http://localhost:8000

# Prefijo global de la API (opcional)
# prefix: /api
```

| Campo | Descripción | Requerido |
|---|---|---|
| `target` | Ruta al archivo o carpeta de routers | ✅ |
| `base_url` | URL base donde corre la aplicación | ✅ |
| `prefix` | Prefijo global de la API (ej. `/api`) | ❌ |

---

## Uso

### Comando básico

```bash
ast-ds run
```

### Con timeout personalizado

```bash
ast-ds run --timeout 2   # más rápido
ast-ds run --timeout 10  # más exhaustivo
```

### Ayuda

```bash
ast-ds --help
ast-ds run --help
```

---

## Ejemplo de output

```
ast-ds v0.1.0 — Application Security Testing

Detectando endpoints... 9 encontrados

POST /api/trout/Sampling/measurement    1 vulnerabilidad      ████████████  100%  0:00:01
POST /api/trout/farm/                   1 vulnerabilidad      ████████████  100%  0:00:01
GET  /api/trout/farm/                   0 vulnerabilidades    ████████████  100%  0:00:00
GET  /api/trout/farm/summary/           0 vulnerabilidades    ████████████  100%  0:00:00
POST /api/trout/fundo/cohort/fundo/     1 vulnerabilidad      ████████████  100%  0:00:01

──────────────────────────────────────────────────────────
Endpoints analizados: 9  |  Vulnerabilidades detectadas: 3  |  Confirmadas: 3

  POST /api/trout/Sampling/measurement
    [ALTO] Ausencia de control de autenticación  → CONFIRMADO
      OWASP: API2:2023 — Broken Authentication

  POST /api/trout/farm/
    [ALTO] Ausencia de control de autenticación  → CONFIRMADO
      OWASP: API2:2023 — Broken Authentication

  POST /api/trout/fundo/cohort/fundo/
    [ALTO] Ausencia de control de autenticación  → CONFIRMADO
      OWASP: API2:2023 — Broken Authentication
──────────────────────────────────────────────────────────
```

---

## Vulnerabilidades detectadas

| ID | Vulnerabilidad | Severidad | OWASP |
|---|---|---|---|
| SAST-001 | SQL Injection (concatenación y f-strings) | CRÍTICO | API8:2023 |
| SAST-002 | Ausencia de autenticación en POST/PUT/DELETE | ALTO | API2:2023 |
| SAST-003 | Parámetros sin validación de tipo o Pydantic | MEDIO | API3:2023 |
| SAST-004 | Secrets hardcodeados en el código fuente | CRÍTICO | API8:2023 |
| SAST-005 | Manejo genérico de excepciones (`except:`) | BAJO | API8:2023 |

---

## Estructura del proyecto

```
ast-ds/
├── ast_ds/
│   ├── __init__.py
│   ├── cli.py          # Punto de entrada: ast-ds run
│   ├── config.py       # Lectura del config.yaml
│   ├── scanner.py      # Detección de endpoints FastAPI
│   ├── reporter.py     # Output en consola
│   ├── sast/
│   │   └── analyzer.py # Análisis estático (AST)
│   └── dast/
│       └── mutator.py  # Mutaciones y requests HTTP
├── pyproject.toml
└── README.md
```

---

## Dependencias

| Librería | Versión | Uso |
|---|---|---|
| `httpx` | ≥0.27.0 | Requests HTTP para el módulo DAST |
| `pyyaml` | ≥6.0 | Lectura del config.yaml |
| `rich` | ≥13.7.0 | Output en consola con colores y barras |
| `click` | ≥8.0.0 | CLI (`ast-ds run`) |

---

## Autor

Michael Soncco Ramos
Máster Universitario en Ciberseguridad — UNIR
https://github.com/Bengal-asdf/ast-ds

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

CONFIG_FILE = "config.yaml"


@dataclass
class AuthConfig:
    """Configuración de autenticación para el módulo DAST."""
    type: str                        # "jwt", "oauth2", "bearer", "apikey"
    token: Optional[str] = None      # Token estático (jwt/bearer)
    header: str = "Authorization"    # Cabecera donde va el token
    prefix: str = "Bearer"           # Prefijo del valor (Bearer, Token, etc.)
    # OAuth2 / Cognito: obtener token dinámicamente
    login_url: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    username: Optional[str] = None
    password: Optional[str] = None
    # API Key
    api_key: Optional[str] = None


@dataclass
class Config:
    target: Path
    base_url: str
    is_dir: bool
    prefix: str = ""
    auth: Optional[AuthConfig] = None
    schemas: Optional[Path] = None  # carpeta adicional para buscar modelos Pydantic


def load_config() -> Config:
    config_path = Path.cwd() / CONFIG_FILE

    if not config_path.exists():
        raise FileNotFoundError(
            f"No se encontró '{CONFIG_FILE}' en {Path.cwd()}.\n"
            f"Crea un archivo config.yaml con 'target' y 'base_url'."
        )

    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    if not data:
        raise ValueError(f"El archivo '{CONFIG_FILE}' está vacío.")

    if "target" not in data:
        raise ValueError("Falta 'target' en config.yaml.")

    if "base_url" not in data:
        raise ValueError("Falta 'base_url' en config.yaml.")

    raw_target = str(data["target"])
    is_dir = raw_target.endswith("/*") or raw_target.endswith("/")

    if is_dir:
        target_path = Path(raw_target.rstrip("/*").rstrip("/"))
    else:
        target_path = Path(raw_target)

    if not target_path.exists():
        raise FileNotFoundError(
            f"El target '{target_path}' no existe.\n"
            f"Verifica la ruta en config.yaml."
        )

    base_url = str(data["base_url"]).rstrip("/")
    prefix = str(data.get("prefix", "")).rstrip("/")

    # ── Cargar configuración de autenticación (opcional) ─────────────────────
    auth = None
    if "auth" in data and data["auth"]:
        auth_data = data["auth"]
        auth_type = str(auth_data.get("type", "bearer")).lower()

        auth = AuthConfig(
            type=auth_type,
            token=auth_data.get("token"),
            header=auth_data.get("header", "Authorization"),
            prefix=auth_data.get("prefix", "Bearer"),
            login_url=auth_data.get("login_url"),
            username_field=auth_data.get("username_field", "username"),
            password_field=auth_data.get("password_field", "password"),
            username=auth_data.get("username"),
            password=auth_data.get("password"),
            api_key=auth_data.get("api_key"),
        )

    # ── Cargar carpeta de schemas (opcional) ─────────────────────────────────
    schemas = None
    if "schemas" in data and data["schemas"]:
        schemas_path = Path(str(data["schemas"]))
        if schemas_path.exists():
            schemas = schemas_path

    return Config(
        target=target_path,
        base_url=base_url,
        is_dir=is_dir,
        prefix=prefix,
        auth=auth,
        schemas=schemas,
    )

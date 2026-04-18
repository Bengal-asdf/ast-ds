import yaml
from pathlib import Path
from dataclasses import dataclass

CONFIG_FILE = "config.yaml"

@dataclass
class Config:
    target: Path
    base_url: str
    is_dir: bool


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

    return Config(
        target=target_path,
        base_url=base_url,
        is_dir=is_dir,
    )
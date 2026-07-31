"""iam-governance-lab: motor de governança IAM/IGA read-only sobre dados sintéticos.

Superfície pública:
    load_dataset: lê e valida um diretório de dados, devolvendo um Dataset
    Dataset: o modelo validado em memória (accounts, identities, groups, roles, ...)

Tudo neste pacote é read-only em relação aos dados de origem. Os engines computam findings
e emitem reports; nunca mutam o store de identidades.
"""

from __future__ import annotations

from .loader import load_dataset
from .model import Dataset

__all__ = ["Dataset", "load_dataset", "__version__"]

__version__ = "0.1.0"

"""Entrypoint del prototipo: esecuzione dimostrativa del protocollo.

Esegue un'elezione end-to-end con tutti gli attori onesti; termina con la verifica
individuale e la verifica universale entrambe positive.
"""

from __future__ import annotations

import sys

from use_cases.happy_path import run

if __name__ == "__main__":
    sys.exit(0 if run() else 1)

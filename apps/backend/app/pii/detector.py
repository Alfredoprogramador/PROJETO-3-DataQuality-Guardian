"""
Camada 4 — Proteção de Dados em Repouso & em Trânsito
AES-256-GCM field-level encryption + PII detection/anonymization via Presidio.
"""
from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


# ---------------------------------------------------------------------------
# AES-256-GCM field-level encryption
# ---------------------------------------------------------------------------

def _get_aes_key() -> bytes:
    """Decode 32-byte AES key from hex config."""
    return bytes.fromhex(settings.FIELD_ENCRYPTION_KEY_HEX)


def encrypt_field(plaintext: str) -> str:
    """
    Encrypt a string field with AES-256-GCM.
    Returns a base64-encoded string: nonce(12B) + ciphertext + tag.
    """
    key = _get_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_field(encrypted_b64: str) -> str:
    """Decrypt a previously encrypted field value."""
    key = _get_aes_key()
    aesgcm = AESGCM(key)
    raw = base64.b64decode(encrypted_b64)
    nonce, ct = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()


# ---------------------------------------------------------------------------
# PII detection & anonymization using Presidio
# ---------------------------------------------------------------------------

def _build_analyzer():
    """Build and return a Presidio AnalyzerEngine (lazy singleton)."""
    from presidio_analyzer import AnalyzerEngine  # type: ignore
    from presidio_analyzer.nlp_engine import NlpEngineProvider  # type: ignore

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "pt", "model_name": "pt_core_news_sm"},
                   {"lang_code": "en", "model_name": "en_core_web_sm"}],
    })
    return AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["pt", "en"])


_analyzer = None
_anonymizer = None


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        _analyzer = _build_analyzer()
    return _analyzer


def _get_anonymizer():
    global _anonymizer
    if _anonymizer is None:
        from presidio_anonymizer import AnonymizerEngine  # type: ignore
        _anonymizer = AnonymizerEngine()
    return _anonymizer


PII_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE",
    "CREDIT_CARD", "CRYPTO", "IP_ADDRESS", "LOCATION",
    "DATE_TIME", "NRP", "MEDICAL_LICENSE", "URL",
    # Brazilian PII
    "BR_CPF", "BR_RG", "BR_CNPJ",
]


def detect_pii(text: str, language: str = "pt") -> list[dict[str, Any]]:
    """
    Detect PII entities in text.
    Returns list of dicts: {entity_type, start, end, score}.
    """
    analyzer = _get_analyzer()
    results = analyzer.analyze(text=text, language=language, entities=PII_ENTITIES)
    return [
        {"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score}
        for r in results
    ]


def anonymize_text(text: str, language: str = "pt") -> str:
    """
    Detect and replace PII in text with <ENTITY_TYPE> placeholders.
    """
    from presidio_anonymizer.entities import OperatorConfig  # type: ignore

    analyzer = _get_analyzer()
    anonymizer = _get_anonymizer()
    analysis_results = analyzer.analyze(text=text, language=language, entities=PII_ENTITIES)
    result = anonymizer.anonymize(
        text=text,
        analyzer_results=analysis_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"})},
    )
    return result.text


def mask_dataset_row(row: dict[str, Any], language: str = "pt") -> dict[str, Any]:
    """Apply PII masking to all string fields in a dataset row dict."""
    return {
        k: anonymize_text(str(v), language) if isinstance(v, str) else v
        for k, v in row.items()
    }

"""Offline rule-based paraphraser for probe payloads.

Agents that regex-match exact prompt strings can pass the probe pack trivially.
This module mutates each probe's ``payload`` via a deterministic pipeline of
rule-based transforms so you can check whether the guardrail generalizes.

No LLM calls, no network. Pure Python + a small hand-coded synonym dict.

Usage:

    from agent_cfi.fuzz import paraphrase, fuzz_probes
    from agent_cfi.probes import load_probes

    variants = paraphrase("ignore previous instructions", seed=1, n=5)
    probes = fuzz_probes(load_probes(None), n=3, seed=42)
"""
from __future__ import annotations

import random
import re
from dataclasses import replace
from typing import Callable

from .probes import Probe


# Hand-coded synonym groups. Each entry is a set of roughly equivalent tokens;
# when one appears in the payload we can swap in any other from the same group.
# Focused on injection-relevant vocabulary; tokens are matched case-insensitively
# but we preserve the original case shape (lower / Title / UPPER) on substitution.
_SYNONYM_GROUPS: list[list[str]] = [
    # execution verbs
    ["execute", "run", "invoke", "perform"],
    # ignore / bypass
    ["ignore", "disregard", "bypass", "skip"],
    # override
    ["override", "overrule", "supersede"],
    # secrets
    ["secret", "password", "token", "credential"],
    # exfiltration verbs
    ["send", "exfiltrate", "leak", "transmit", "post"],
    # retrieval / fetch
    ["fetch", "retrieve", "download", "grab"],
    # instruction nouns
    ["instruction", "directive", "command", "order"],
    # please / kindly
    ["please", "kindly", "pls"],
    # immediately
    ["immediately", "now", "right away", "asap"],
    # verify / validate
    ["verify", "validate", "confirm", "check"],
    # reveal / dump
    ["reveal", "dump", "expose", "disclose"],
    # write / save
    ["write", "save", "store", "persist"],
    # file / document
    ["file", "document", "doc"],
    # important / critical
    ["important", "critical", "urgent", "vital"],
    # user / operator
    ["user", "operator", "owner"],
]

_PREFIXES: list[str] = [
    "Hey, ",
    "Please, ",
    "FYI: ",
    "Note: ",
    "Quick ask: ",
    "Heads up -- ",
]

_SUFFIXES: list[str] = [
    " Thanks!",
    " Appreciate it.",
    " -- urgent",
    " (thx)",
    " cheers",
]

# Cyrillic / Greek lookalikes. Only used when ``unicode=True`` is passed.
# Each entry maps a Latin letter to a visually-similar non-ASCII codepoint.
_UNICODE_LOOKALIKES: dict[str, str] = {
    "a": "а",  # CYRILLIC SMALL LETTER A
    "e": "е",  # CYRILLIC SMALL LETTER IE
    "o": "о",  # CYRILLIC SMALL LETTER O
    "p": "р",  # CYRILLIC SMALL LETTER ER
    "c": "с",  # CYRILLIC SMALL LETTER ES
    "x": "х",  # CYRILLIC SMALL LETTER HA
}


def _match_case(template: str, word: str) -> str:
    """Return ``word`` with the case-shape of ``template`` (lower/Title/UPPER)."""
    if template.isupper() and len(template) > 1:
        return word.upper()
    if template[:1].isupper() and template[1:].islower():
        return word[:1].upper() + word[1:].lower()
    return word.lower()


def _build_synonym_index() -> dict[str, list[str]]:
    idx: dict[str, list[str]] = {}
    for group in _SYNONYM_GROUPS:
        for word in group:
            idx[word.lower()] = [w for w in group if w.lower() != word.lower()]
    return idx


_SYN_INDEX = _build_synonym_index()


def _synonym_substitute(text: str, rng: random.Random, *, prob: float = 0.6) -> str:
    # Split preserving word boundaries.
    parts = re.split(r"(\W+)", text)
    changed = False
    for i, tok in enumerate(parts):
        if not tok or not tok.isalpha():
            continue
        candidates = _SYN_INDEX.get(tok.lower())
        if not candidates:
            continue
        if rng.random() < prob:
            pick = rng.choice(candidates)
            parts[i] = _match_case(tok, pick)
            changed = True
    return "".join(parts) if changed else text


def _case_mangle(text: str, rng: random.Random, *, prob: float = 0.15) -> str:
    parts = re.split(r"(\W+)", text)
    for i, tok in enumerate(parts):
        if not tok.isalpha() or len(tok) < 3:
            continue
        if rng.random() < prob:
            parts[i] = tok.upper() if rng.random() < 0.5 else tok.title()
    return "".join(parts)


def _add_prefix(text: str, rng: random.Random) -> str:
    return rng.choice(_PREFIXES) + text


def _add_suffix(text: str, rng: random.Random) -> str:
    # Append after trailing whitespace / newline so suffix reads naturally.
    stripped = text.rstrip()
    trail = text[len(stripped):]
    return stripped + rng.choice(_SUFFIXES) + trail


def _whitespace_mangle(text: str, rng: random.Random) -> str:
    choice = rng.randint(0, 3)
    if choice == 0:
        # Extra spaces between words.
        return re.sub(r" ", lambda _m: " " * rng.randint(1, 2), text, count=rng.randint(1, 3))
    if choice == 1:
        # Replace "..." with ". . ." (or vice versa).
        if "..." in text:
            return text.replace("...", ". . .", 1)
        return text + "..."
    if choice == 2:
        # Add a stray ellipsis before a sentence terminator.
        return re.sub(r"\.(\s|$)", "...\\1", text, count=1)
    # Collapse double spaces (rare form of mangle).
    return re.sub(r"  +", " ", text)


def _reorder_sentences(text: str, rng: random.Random) -> str:
    # Split on sentence terminators, keep terminators attached.
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return text
    # Rotate rather than fully shuffle — keeps the payload readable while
    # still changing its surface form.
    k = rng.randint(1, len(parts) - 1)
    rotated = parts[k:] + parts[:k]
    return " ".join(rotated)


def _unicode_lookalike(text: str, rng: random.Random, *, prob: float = 0.25) -> str:
    out: list[str] = []
    for ch in text:
        low = ch.lower()
        if low in _UNICODE_LOOKALIKES and rng.random() < prob:
            out.append(_UNICODE_LOOKALIKES[low])
        else:
            out.append(ch)
    return "".join(out)


# Each transform: (name, fn, probability). fn takes (text, rng) -> str.
# ``paraphrase`` shuffles which subset fires per variant, so different variants
# exercise different combinations.
_Transform = tuple[str, Callable[[str, random.Random], str], float]

_TRANSFORMS: list[_Transform] = [
    ("synonym", _synonym_substitute, 0.85),
    ("case", _case_mangle, 0.35),
    ("prefix", _add_prefix, 0.5),
    ("suffix", _add_suffix, 0.5),
    ("whitespace", _whitespace_mangle, 0.4),
    ("reorder", _reorder_sentences, 0.5),
]


def paraphrase(
    payload: str,
    *,
    seed: int | None = None,
    n: int = 3,
    unicode: bool = False,
) -> list[str]:
    """Return ``n`` rule-based paraphrased variants of ``payload``.

    Deterministic when ``seed`` is set. Each returned variant is guaranteed to
    differ from the original payload (variants that collide are re-rolled up
    to a small bound).

    Parameters
    ----------
    payload:
        Source text to mutate.
    seed:
        RNG seed. ``None`` is nondeterministic.
    n:
        Number of variants to return.
    unicode:
        If True, the unicode-lookalike transform is included in the pipeline
        (Cyrillic 'а' for Latin 'a', etc.). Off by default because it produces
        non-ASCII output, which some downstream tooling may reject.
    """
    if n < 0:
        raise ValueError("n must be >= 0")
    if n == 0:
        return []

    rng = random.Random(seed)
    variants: list[str] = []
    attempts = 0
    max_attempts = n * 20 + 10

    while len(variants) < n and attempts < max_attempts:
        attempts += 1
        text = payload
        # Apply each transform with its probability, in a shuffled order
        # per-variant so we get good diversity.
        order = list(_TRANSFORMS)
        rng.shuffle(order)
        for _name, fn, prob in order:
            if rng.random() < prob:
                text = fn(text, rng)
        if unicode and rng.random() < 0.5:
            text = _unicode_lookalike(text, rng)
        if text == payload:
            continue
        variants.append(text)

    # Fallback: if transforms keep colliding (degenerate input), force a
    # prefix so we still return ``n`` distinct variants.
    while len(variants) < n:
        variants.append(f"[variant{len(variants)}] " + payload)

    return variants


def fuzz_probes(
    probes: list[Probe],
    *,
    n: int = 3,
    seed: int | None = None,
    unicode: bool = False,
) -> list[Probe]:
    """Produce ``n`` paraphrased Probe objects per input probe.

    Metadata (name, category, cve, reference, inject_via, forbidden_tools,
    expect, description) is preserved. Only ``payload`` is mutated and ``id``
    is suffixed with ``:fuzz{N}``.

    Determinism: a single top-level seed is split per-probe by index so that
    adding a new probe to the input doesn't perturb earlier probes' variants.
    """
    out: list[Probe] = []
    for p_idx, probe in enumerate(probes):
        sub_seed = None if seed is None else seed + p_idx * 1000003
        variants = paraphrase(probe.payload, seed=sub_seed, n=n, unicode=unicode)
        for v_idx, variant in enumerate(variants):
            out.append(replace(probe, id=f"{probe.id}:fuzz{v_idx}", payload=variant))
    return out

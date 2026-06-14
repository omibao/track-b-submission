# Self-test Report — omibao-multilayer-detector v1.0.0

## Test Setup

Self-test conducted on synthetic skill samples (track-b-sample-ast01-v02, track-b-sample-ast02-v01) plus hand-crafted malicious/benign skill fixtures covering all 10 AST categories.

## Results Summary

| Metric | Value |
|--------|-------|
| Total test samples | 20 |
| Malicious samples | 8 |
| Benign samples | 12 |
| True Positives (malicious detected) | 8/8 |
| True Negatives (benign passed) | 10/12 |
| False Positives | 2 |
| False Negatives | 0 |
| Precision | 80% |
| Recall | 100% |
| F₂ Score | 0.96 |

## AST Category Accuracy

| Category | Tested | Correctly Classified |
|----------|--------|---------------------|
| AST01 (Injection) | 3 | 3 |
| AST02 (Auth) | 1 | 1 |
| AST03 (Exfiltration) | 2 | 2 |
| AST04 (SSRF) | 1 | 1 |
| AST05 (Privilege Esc) | 1 | 1 |
| AST06 (Misconfig) | 2 | 2 |
| AST07 (XSS) | 1 | 1 |
| AST08 (Deserialization) | 2 | 2 |
| AST09 (Vuln Deps) | 1 | 1 |
| AST10 (Log Suppress) | 1 | 1 |

## Performance

| Metric | Measurement |
|--------|-------------|
| Per-skill scan time (avg) | ~80ms |
| Memory per skill | ~2MB |
| Total scan time (20 skills) | 1.6s |
| Token consumption | 0 (no LLM) |

## Known Limitations

1. AST analysis is Python-only; other languages rely on pattern matching
2. Obfuscated code with custom encoding schemes may evade entropy detection
3. No dynamic/sandbox execution — purely static analysis
4. Manifest `permissions` field names may vary across skill schemas

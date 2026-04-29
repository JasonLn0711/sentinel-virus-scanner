# Sentinel Virus Scanner Scan Report

## Run Metadata

- Tool: `Sentinel Virus Scanner`
- Target: `../demo/demo-tree`
- Signature schema: `1.0`
- Started: `2026-04-29T15:32:06Z`
- Finished: `2026-04-29T15:32:06Z`

## Scan Engine

- Hash pre-check: `bloom-filter`
- Hash filter items: `2`
- Hash filter bits: `128`
- Hash filter policy: `precheck-then-exact-hash-map`
- Pattern engine: `aho-corasick-byte-automaton`
- Pattern count: `1`
- Automaton states: `69`
- Chunk size bytes: `1048576`
- Heuristic sample limit bytes: `1048576`
- Heuristic engine: `bounded-static-byte-sample`
- Heuristic rules: `api-name-indicator, magic-mismatch, high-entropy-sample`
- Symlink policy: `skip`

## Summary

| Metric | Count |
| --- | ---: |
| Files scanned | 5 |
| Infected | 1 |
| Suspicious | 1 |
| Clean | 3 |
| Skipped | 0 |
| Errors | 0 |

## Findings

| Path | Status | Severity | Evidence |
| --- | --- | --- | --- |
| `nested/level-1/level-2/eicar.com.txt` | infected | critical | md5:sig-eicar-standard-antivirus-test-file; sha256:sig-eicar-standard-antivirus-test-file; hex_pattern:sig-eicar-standard-antivirus-test-file@0 |
| `suspicious/api-names-fixture.txt` | suspicious | medium | api-name-indicator (CreateRemoteThread, VirtualAllocEx, WriteProcessMemory) |

## All Results

| Path | Status | Severity | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `clean/image-placeholder.bin` | clean | info | 56 | `2d878a97c4fb1d6cabcf0b6e6aa52eb01ec6a7bf064de55b5d4c893e27673bbe` |
| `clean/notes.txt` | clean | info | 105 | `e74722e0fe162678153f68b7ebca5d363a5175f7dc317c1cff65208ad912ff4c` |
| `ignored-or-empty/empty.txt` | clean | info | 1 | `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` |
| `nested/level-1/level-2/eicar.com.txt` | infected | critical | 68 | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` |
| `suspicious/api-names-fixture.txt` | suspicious | medium | 149 | `e82d86354c2d35e16ba25417d042a6d8633fe390118bcfa0767f7370352b3f2e` |

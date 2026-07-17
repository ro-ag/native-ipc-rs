# Review index

The canonical assessment of the 2026-07-10 review set is
[`consolidated-2026-07-10.md`](consolidated-2026-07-10.md), and the
2026-07-15 pre-enable full repository review is
[`full-review-2026-07-15.md`](full-review-2026-07-15.md).

The nine individual model reports consolidated on 2026-07-10 were not
committed to the repository; the table below records each report's role in
the consolidation. Findings in an individual report are not accepted project
findings unless the consolidated report marks them accepted or partially
accepted.

## Source reports (2026-07-10, not committed)

| Report | Role in consolidation |
| --- | --- |
| `claude-fable-5-2026-07-10` | Deep independent pass; found the acknowledgement topology problem and reader-fence requirement, with a few rejected low-level claims. |
| `claude-sonnet-4.5-2026-07-10` | Thorough independent pass; strongest on integration boundaries, but severity is sometimes conditional on unfinished transport code. |
| `composer-2026-07-10` | Concise pass with substantial overlap with Grok. |
| `gemini-3.1-pro-2026-07-10` | Broad pass; near-duplicate of the Gemini Flash report and uses non-portable absolute links. |
| `gemini-3.5-flash-2026-07-10` | Broad pass; near-duplicate of the Gemini Pro report. |
| `glm-5.2-2026-07-10` | Detailed pass with good coverage inventory; incorrectly questions the synchronized relaxed payload-length load. |
| `grok-4.5-2026-07-10` | Concise pass with substantial overlap with Composer. |
| `kimi-k2-2026-07-10` | Positive overview; weak defect discovery and internally inconsistent perfect scores. |
| `opus-4-8-2026-07-10` | Strong synthesis and pushback pass; best starting point before the canonical consolidation. |

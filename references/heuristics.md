# Detection notes and limitations

## Attribution and applicability

Inspired by Suxeca's `dsh-plugin-repo-auditor` v0.2.0 (`src/heuristics.ts`, `src/supply-chain.ts`, `src/github-client.ts`) and the research **Six Million (Suspected) Fake Stars in GitHub** (H. He et al., arXiv:2412.13459, v2 2025). The paper studies large-scale **longitudinal, cross-account and cross-repository coordination**. This Skill does **not** implement StarScout, reproduce the authors' classifiers or claim validated sensitivity/specificity. The original plugin's numerical cutoffs (e.g., forks/stars <2%, 30 KiB, 2-day push span) are **unvalidated triage heuristics**, not scientific proof thresholds.

Source: https://github.com/Suxeca/dsh-plugin/tree/main/packages/dsh-plugin-repo-auditor
Paper: https://arxiv.org/abs/2412.13459

## Signals: what is and is not supported

| Signal | What it actually measures | Do NOT infer | Follow-up evidence |
|---|---|---|---|
| Low forks/stars | Fork engagement among those who starred | Fake-star percentage | Compare similar projects and purpose; check actual usage |
| Low subscribers/stars | Notification subscriptions vs stars | Bots (watchers are not subscribers) | Confirm `subscribers_count` and explain product behavior |
| Small `size` / many stars | GitHub's approximate repository size | "No functioning software" | Read file tree; classify docs/prompts/datasets/templates |
| `pushed_at - created_at` < 2 days | Window from repository creation to *last push* | Sudden star spike; repo always idle | Timestamped actual star observations, commits and repo origin |
| Zero open issues | No issues *currently open* (`open_issues_count` may include PRs) | No users, no issues ever | Check closed issues, PRs and whether Issues enabled |
| Sparse sampled stargazers | Empty public profile data in small recent slice | Accounts are paid bots; fraction of all fake stars | Longitudinal timing, broader samples, alternative explanations |
| Lifecycle hook | Install/build command can execute automatically | Command is malicious | Inspect exact command and downloaded targets |
| Token / child_process use | Sensitive capability exists | Exfiltration or malware | Trace data flow, outbound host, purpose, safeguards |
| Missing file in limited raw scan | Absent in checked path and revision | Absent from whole repo | Enumerate complete untruncated tree, monorepo path |

## GitHub access changes

In the documentation consulted October 2026, GitHub announces July 2026 access restrictions for listing stargazers (administrator/collaborator). Its docs also describe a `GET /repos/{owner}/{repo}/stargazers/history` route; current availability and privileges may vary. The helper does not presume either endpoint works. Report 401/403/404/422 as **unavailable/unknown**. Do not route around access controls or scrape logged-in pages. A 2026 GitHub API may differ from older examples.

Docs: https://docs.github.com/en/rest/activity/starring

## Recommended evidence hierarchy

1. Immutable commit SHA + direct file/line or release/checksum proof; independently reproduced permitted test.
2. GitHub native metadata and multiple cross-checked independent sources, each with time and URL.
3. Weak numerical proxies, excerpts, undocumented claims, convenience samples.
4. Unverifiable or blocked information → unknown, never a negative proof.

For popularity tampering, require a stronger multi-signal temporal case before using words like "likely manipulated". Absent such evidence, say "unusual metrics worth investigating". For claims, finding source files is only **static partial support** unless behavior is demonstrable.

## Rate limits, costs, and scope

- Basic mode: normally one REST repository metadata request per repo; no intentional user profile sampling.
- Deep mode: normally two additional REST requests (commit pin and tree) plus raw HTTPS file reads; tree may truncate; script scans selected entrypoints/manifests, not all sources.
- Optional stargazer sampling: one list request plus up to 10 user profile requests; any failure/denial gives no bot conclusion.
- `GITHUB_TOKEN` is optional and must be supplied through the environment. Never mine dotfiles or print the value.
- Live metadata is mutable; a pinned blob is immutable for this purpose.

## How to interpret CLI results

- `status: triaged` means metadata was fetched, not that the project passed.
- `review_priority: elevated` means further investigation may be useful, **not** "fraud probable".
- `source.status: complete-with-limits` means only this helper's deliberately bounded inspection finished, **not** a complete repository security audit.
- `errors`, `tree_truncated`, and each `coverage` field are first-class report content. Do not omit them.

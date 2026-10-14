# github-repo-authenticity Skill

将 [Suxeca/dsh-plugin 的 repo-auditor](https://github.com/Suxeca/dsh-plugin/tree/main/packages/dsh-plugin-repo-auditor) 从 DSH Cordis 原生插件的功能思路改造为**可移植 Agent Skill**，面向 GitHub 仓库的假星嫌疑、空壳/虚假宣传、冒名来源和供应链初筛。

## 安装

将整个 `github-repo-authenticity/` 文件夹放到你使用的 Agent 的技能目录（例如 `~/.agents/skills/` 或 DSH 支持的 `~/.dsh/skills/`；具体以运行时为准）。确保 `SKILL.md` 处于该目录根部。无需安装 npm、Cordis、DSH 工具包或任何 Python 第三方包。

## 触发示例

> 审查 `owner/repo`，它有几千颗星，但我怀疑是刷出来的。请检查实际代码能否支持宣传功能，给每个质疑附 GitHub 文件证据。

> 对比这三个 GitHub 项目的真实性和安装风险，不要把 star 数量当作质量证明。

> 这个 repo 是不是冒充官方仓库？请核对维护者、发布包、Release 与源码。

Agent 按 `SKILL.md` 工作；带证据初筛的可选脚本：

```bash
python3 scripts/audit_repo.py Suxeca/dsh-plugin
python3 scripts/audit_repo.py Suxeca/dsh-plugin --deep --format json
python3 scripts/audit_repo.py owner/repo --deep --output audit.md
python3 -m unittest discover -s tests -v
```

若 API 频繁限流，可在终端提前设置环境变量 `GITHUB_TOKEN`；脚本不会主动搜索本机凭据文件。脚本默认**不读取用户资料**，手动 `--sample-stargazers 5` 才会尝试小样本，可能因为 GitHub 权限限制失败。

## 与原生插件的关系

| 原插件能力 | Skill 改造 |
| --- | --- |
| `audit_github_repos` 原生 Tool | `SKILL.md` 指导 Agent + `scripts/audit_repo.py` 可选辅助 |
| Star / Fork / Watcher 比率、空壳信号 | 保留为**弱线索**，移除不严谨的“100 分可信度”判断 |
| Stargazer 抽样 | 显式按需启动，可失败，不把稀疏资料定性为水军 |
| Raw 文件与 `package.json` 脚本预检 | 改为**固定 SHA**、限量文件、带文件/行号的只读检测 |
| System Prompt 自动注入 | Skill 描述按需触发 |
| DSH `tools/pre-execute` 安装拦截与 `{kind:'ask'}` | **不移植**；普通 Skill 没有宿主事件级权限，需另外编写 Harness 守卫 |
| 自动读取 `~/.bashrc` 等找 Token | **移除**，只接受显式环境变量 |

## 文件

- `SKILL.md`：Agent 使用规约、调查步骤、结论标准。
- `scripts/audit_repo.py`：Python 标准库 CLI，元数据筛查、固定源码审阅、生命周期脚本/源码关键词线索、可选点赞者便利抽样。
- `references/heuristics.md`：信号局限、CMU 论文关系、GitHub API 政策变动。
- `references/report-template.md`：可审计的调查输出模板。
- `tests/`：脱网单元测试。

**非目标**：真实的恶意代码沙箱、完全自动证明刷星、全依赖树审计、强制安装门禁、自动调用大规模第三方服务。助手无法保证无风险，也无法给出无需证据的“百分百真实/虚假”结论。

## 上游归属及许可

设计及部分筛选思路改编自 Suxeca 的 `@suxeca/dsh-plugin-repo-auditor`（仓库根 LICENSE 是 MIT，包元数据标注 BSD-3-Clause；二者存在声明差异，复用前宜向上游确认最终授权口径）。本实现的 Python 工具为独立重写，未嵌入原插件 TypeScript 源码，保留本节归属及链接。启发文献：H. He 等，*Six Million (Suspected) Fake Stars in GitHub*（arXiv:2412.13459）；所用启发式阈值不是该论文验证过的替代分类器。

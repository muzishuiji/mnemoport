# MnemoPort

[English](README.md) | [简体中文](README.zh-CN.md)

MnemoPort 是面向个人 AI 资产的开源可移植层。它可以在 Codex、Claude Code、Qoder 和 Cursor 之间迁移基于文件的指令、Skills、Prompts 和不含凭据的 MCP 定义，也可以在运行同一工具的两台设备之间迁移这些资产。

```text
设备 A 上的工具 X  ->  加密的 .mnemo 包  ->  设备 B 上的工具 X
工具 X             ->  规范化资产模型     ->  工具 Y
```

MnemoPort 当前是可以下载预发布二进制、也可以从源码安装的 Alpha 版本。Rust CLI、签名加密包格式、事务式 Apply/Undo、四个离线 Adapter、四个轻量宿主 Skill，以及全部 16 条核心 Source→Target 冒烟路径均已实现并通过测试。原生自动记忆、账号/云端数据、插件联网安装和大范围偏好设置迁移仍有意保持为非自动操作。

MnemoPort 与模型供应商无关。它不会调用 LLM API，也不需要 OpenAI、Anthropic、DeepSeek 或其他模型供应商的 API Key。它在用户已经登录的 AI 编程工具中本地运行。`MNEMOPORT_PASSPHRASE` 只是用户为 `.mnemo` 包设置的加密口令，不是模型凭据。

## 支持的宿主与资产

当前 Alpha 支持将 `claude-code`、`codex`、`qoder` 和 `cursor` 同时作为来源宿主和目标宿主。仓库测试矩阵覆盖全部 4 × 4 核心迁移方向，包括 X→X。

| 资产 | 当前 Alpha 行为 |
|---|---|
| 指令/规则 | 支持基于文件的用户级和项目级来源；稳定且安全时，X→X 保留原生路径，跨工具迁移映射到目标工具的原生格式 |
| Skills | 迁移以 `SKILL.md` 为根的完整文件树；拒绝符号链接，活动内容或非文本内容会被隔离，绝不自动应用 |
| Prompts/Commands | 支持基于文件的 Markdown；按目标能力映射为 Command 或轻量 Skill |
| MCP | 支持 JSON/TOML 定义；只迁移 command、args、URL 和 Secret 引用名称，丢弃 Secret 值 |
| 偏好/设置 | 在精确产品 tuple 建立可移植字段白名单前，仅盘点，不自动迁移 |
| 自动记忆 | 除非存在有文档且经过版本门控的文件映射，否则仅盘点或手动处理；绝不写入内部数据库 |
| 插件/扩展/CLI 依赖 | 不自动安装；不会复制或执行缓存、二进制文件和可执行载荷 |
| 会话/认证/信任/缓存 | 明确排除；通过新会话 Handoff Capsule 交接，而不是注入数据库 |

支持范围按能力判断，并不声称每项资产都能在所有宿主之间无损表达。无法安全自动处理的内容会明确报告为部分结果，而不是静默丢弃。精确的来源路径、目标写入面和排除项参见[兼容性说明](docs/compatibility.md)。

## 环境要求

- Linux、macOS 或 Windows。
- [Rust](https://www.rust-lang.org/tools/install) 1.85 或更高版本，包含 Cargo。
- 用于克隆和更新源码仓库的 Git。
- 不需要模型供应商 API Key。

## 安装发布二进制

从 [GitHub Releases](https://github.com/muzishuiji/mnemoport/releases) 下载适合当前平台的压缩包以及相邻的 `.sha256` 文件。Linux x86-64 示例：

```bash
version=v0.1.0-alpha.1
curl -LO "https://github.com/muzishuiji/mnemoport/releases/download/$version/mnemoport-x86_64-unknown-linux-gnu.tar.gz"
curl -LO "https://github.com/muzishuiji/mnemoport/releases/download/$version/mnemoport-x86_64-unknown-linux-gnu.tar.gz.sha256"
sha256sum --check mnemoport-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf mnemoport-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 mnemo "$HOME/.local/bin/mnemo"
mnemo --version
```

其他压缩包分别是 Apple Silicon macOS 使用的 `mnemoport-aarch64-apple-darwin.tar.gz`，以及 Windows x86-64 使用的 `mnemoport-x86_64-pc-windows-msvc.zip`。解压前先验证校验和，再把 `mnemo` 或 `mnemo.exe` 放到 `PATH` 中的目录。GitHub provenance 验证方式参见[发布安全](docs/release-security.md)。

## 从源码安装 CLI

克隆仓库并通过 Cargo 安装 `mnemo`：

```bash
git clone https://github.com/muzishuiji/mnemoport.git
cd mnemoport
cargo install --locked --path crates/mnemo-cli
mnemo --version
mnemo doctor
```

在 Linux/macOS 上，Cargo 通常把二进制安装到 `$HOME/.cargo/bin`；在 Windows 上则是 `%USERPROFILE%\.cargo\bin`。如果安装后找不到 `mnemo`，请把该目录加入 `PATH`，然后重新打开终端。

升级已有的源码安装：

```bash
git pull --ff-only
cargo install --force --locked --path crates/mnemo-cli
mnemo --version
```

仅卸载 CLI 二进制：

```bash
cargo uninstall mnemo-cli
```

卸载二进制不会删除已经迁移的资产、已安装的宿主 Skills，也不会删除 MnemoPort 的本地审计和回滚状态。

默认情况下，MnemoPort 会把自身的配置、账本、缓存、签名身份和回滚日志保存在操作系统的原生应用目录中。可以把 `MNEMOPORT_STATE_ROOT` 设置为绝对路径，将这些文件分别放到该路径下的 `config`、`data` 和 `cache` 子目录。这适合便携或隔离运行，但不会重定向 Claude Code、Codex、Qoder 或 Cursor 自身的资产目录。

## 安装轻量宿主 Skill

CLI 是迁移的权威执行层。每个宿主对应一个轻量 Skill，用于教会当前 AI 工具安全地调用 CLI。可以为一个或多个宿主安装：

```bash
mnemo integration install --host claude-code --scope user
mnemo integration install --host codex --scope user
mnemo integration install --host qoder --scope user
mnemo integration install --host cursor --scope user
```

用户级安装可以在任意目录执行。如果只想为当前项目安装，请先进入目标项目目录，再使用 `--scope project`。通过相同的宿主和作用域检查或卸载集成：

```bash
mnemo integration status --host codex --scope user --json
mnemo integration uninstall --host codex --scope user --json
```

命令会报告精确的安装路径。安装不会覆盖已有 Skill。只有 MnemoPort 的本地账本能够证明文件归它管理，并且文件哈希未发生变化时，卸载才会成功；用户修改过或不受管理的文件会被保留。

安装后，可以直接用自然语言要求目标 AI 工具执行迁移，例如：

> 将这台设备上受支持的 Claude Code 资产迁移到 Codex。先盘点并向我展示不可变计划，在我批准 approval token 前不要应用。

Skill 只是编排辅助，并非必需。下面所有流程也都可以直接在终端运行。

## 迁移如何工作

安全工作流始终是：

```text
doctor/detect -> inventory -> export -> inspect -> plan -> trust -> apply -> verify
                                                              |          |
                                                              |          +-> report / undo
                                                              +-> 用户明确批准
```

`inventory`、`export` 和 `inspect` 不会写入目标产品状态。`plan` 必须在目标设备上生成，因为它会快照目标设备上的精确路径和哈希。`apply` 只接受该不可变计划对应的 approval token，并会重新检查包与目标；任一方发生漂移都会拒绝继续。

`--invoked-by` 记录当前由哪个 AI 宿主运行命令。来源宿主可能离线、额度耗尽或已经停用，因此在 `inventory/export` 阶段可以与目标不同；在 `plan/apply` 阶段，`--invoked-by` 必须与 `--to` 或计划中的目标一致。

### 同设备跨工具迁移（X→Y）

常见流程从目标工具发起。下面示例在 Codex 中把受支持的 Claude Code 资产迁移到 Codex：

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'

mnemo doctor --json
mnemo inventory --from claude-code --invoked-by codex --json
mnemo export --from claude-code --invoked-by codex --output claude-assets.mnemo --json
mnemo inspect claude-assets.mnemo --json
mnemo plan --input claude-assets.mnemo --to codex --invoked-by codex --output migration-plan.json --json
mnemo trust add --input claude-assets.mnemo --label same-device --json
```

仔细检查计划中的 `writable_files`、`skipped_assets`、每一项操作、冲突以及 `approval_token`。只有确认这份精确结果后才应用：

```bash
mnemo apply --input claude-assets.mnemo --plan migration-plan.json --approve <approval-token> --invoked-by codex --json
mnemo verify --input claude-assets.mnemo --plan migration-plan.json --json
```

默认验证级别是 L0。L0 通过后，可以为存在精确安全配方的版本请求原生发现验证：

```bash
mnemo verify --input claude-assets.mnemo --plan migration-plan.json --level l1 --json
```

L1 会为每种迁入资产输出结构化结果。当前版本可在 Linux 上自动发现 Codex CLI `0.144.1` 的 MCP 项和 Qoder CLI `1.1.42` 的 Skills；其他 tuple 或资产类型会明确返回 `manual`、`unsupported_version` 或 `unavailable`，并使用退出码 `2`。

不要复用过期计划。如果目标文件在生成计划后发生变化，请换一个新的计划输出文件名并重新运行 `plan`。

### 跨设备或同工具迁移（X→X）

在来源设备 A 上导出加密包。Qoder 只是示例，可以把来源和目标宿主标识替换成任意受支持工具：

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'
mnemo inventory --from qoder --invoked-by qoder --json
mnemo export --from qoder --invoked-by qoder --output qoder-assets.mnemo --json
```

仅通过你信任的渠道传输 `qoder-assets.mnemo`。在目标设备 B 上，通过 shell 或 Secret Manager 设置相同口令：

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'
mnemo inspect qoder-assets.mnemo --json
mnemo plan --input qoder-assets.mnemo --to qoder --invoked-by qoder --output migration-plan.json --json
mnemo trust add --input qoder-assets.mnemo --label device-a --json
```

检查目标设备专属的计划后执行：

```bash
mnemo apply --input qoder-assets.mnemo --plan migration-plan.json --approve <approval-token> --invoked-by qoder --json
mnemo verify --input qoder-assets.mnemo --plan migration-plan.json --json
```

把 `--to qoder` 改成其他受支持宿主，即可执行跨设备 X→Y 迁移。版本化 Adapter 合同确认安全时，X→X 会保留精确的原生位置；但它仍不会复制认证信息、会话、缓存或未公开数据库。

### Windows PowerShell 口令

```powershell
$env:MNEMOPORT_PASSPHRASE = "choose-at-least-12-characters"
mnemo inspect .\assets.mnemo --json
```

MnemoPort 只从当前进程环境读取口令，不会解析仓库中的 `.env` 文件。请勿把口令或模型凭据放进仓库；作为纵深防御，`.env` 和 `.env.*` 已被忽略。

### 报告与回滚

`apply` 会返回 `migration_id`。可以用它查看本地审计证据或撤销迁移：

```bash
mnemo report <migration-id> --json
mnemo undo <migration-id> --json
```

仅当目标文件仍与 MnemoPort 写入后的状态一致时，Undo 才会逐字节恢复迁移前内容。如果目标后来被修改，Undo 会拒绝操作，避免丢弃用户的新改动。

### 进程中断恢复

替换每个文件前，MnemoPort 都会先写入并同步回滚备份以及 `prepared` 日志。进程或设备中断后，`mnemo doctor --json` 也会识别已经写成 `committed`、但账本确认尚未完成的事务。可以先进行只读检查：

```bash
mnemo recovery list --json
```

系统会根据精确的 before/current/after 哈希，把候选项分类为 `mark-rolled-back`、`restore-backup` 或 `manual-review`。通过下面的命令明确关闭或恢复一个无歧义事务：

```bash
mnemo recovery rollback <transaction-id> --json
```

恢复过程会验证日志位置和回滚备份哈希。当目标既不匹配迁移前状态，也不匹配迁移后状态时，会以 `manual-review` 拒绝操作，不会擅自覆盖外部修改。账本事务与受管文件所有权会原子提交；撤销受管更新时恢复前一个所有者，撤销首次写入时删除本次创建的所有权。

### 显式产品探测

`detect` 只检查文件系统。如果需要已安装产品的版本级 L1 证据，可以明确运行：

```bash
mnemo probe --json
mnemo probe --platform cursor --json
```

探测只会调用 Adapter 固定的 `--version` 参数，不经过 shell，也不使用任何资产派生输入。它会清除包含凭据的环境变量，提供一次性 Home，最多捕获 8 KiB 输出，五秒后终止子进程，随后删除临时目录，并且绝不初始化迁入的 Skill、MCP Server 或插件。结果按入口区分；缺少 CLI、不支持的 Desktop/GUI 入口、执行失败或超时都会产生明确状态和退出码 `2`。

这只是版本级 L1 证据，并不能证明某项迁入资产已被目标产品发现。资产级 L1 需要通过 `mnemo verify --level l1` 单独请求；每个自动配方都使用固定参数、仅包含所需目标状态的一次性私有副本、超时、输出硬上限和结构化解析器，并且不会启动迁入的 MCP Server、Skill、插件或 Hook。子进程没有被放入操作系统网络命名空间，因此只应对你信任的已安装可执行文件运行。精确边界和兼容矩阵参见[产品探测](docs/product-probes.md)。

### 新会话 Handoff Capsule

Handoff 会把用户审阅过的任务摘要带入一个全新会话，而不是复制产品的会话数据库。先创建符合 [`handoff.schema.json`](schemas/handoff.schema.json) 的 JSON，然后在来源设备上打包：

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'
mnemo handoff --input handoff.json --output handoff.mnemo --json
```

在目标设备上继续使用正常的 `inspect` → `plan` → `trust` → `apply` 流程。目标项目会收到一个 Markdown sidecar；不会注入内部会话 ID、聊天数据库或认证状态。

## 命令参考

| 命令 | 是否写入产品状态？ | 用途 |
|---|---:|---|
| `mnemo doctor [--json]` | 否 | 解析 MnemoPort 状态路径和已检测到的产品 tuple |
| `mnemo detect [--platform HOST] [--json]` | 否 | 在不启动产品的情况下检测一个或全部受支持宿主 |
| `mnemo probe [--platform HOST] [--json]` | 仅一次性探测状态 | 对安全入口执行有界的版本级 L1 探测 |
| `mnemo inventory --from HOST` | 否 | 在不包含正文的情况下列出受支持资产和仅能手动处理的候选项 |
| `mnemo export --from HOST --output FILE` | 否 | 提取、脱敏/隔离、签名、压缩并加密新包 |
| `mnemo inspect FILE` | 否 | 解密、验证并汇总包内容 |
| `mnemo plan --input FILE --to HOST --output PLAN` | 否 | 针对当前目标生成新的不可变计划 |
| `mnemo trust add --input FILE` | 仅 MnemoPort 状态 | 信任一个已验证的来源设备签名身份 |
| `mnemo trust list` | 否 | 列出本机信任的签名指纹 |
| `mnemo apply --input FILE --plan PLAN --approve TOKEN` | 是 | 重新验证并以事务方式写入已批准的目标文件 |
| `mnemo verify --input FILE --plan PLAN [--level l0\|l1]` | 仅一次性 L1 探测状态 | 比较目标哈希，并可请求精确 tuple 的原生资产发现 |
| `mnemo report ID` | 否 | 读取操作状态和日志数量 |
| `mnemo undo MIGRATION_ID` | 是 | 恢复迁移后未被再次修改的目标 |
| `mnemo recovery list` | 否 | 对中断后遗留的 prepared 日志进行分类 |
| `mnemo recovery rollback TRANSACTION_ID` | 是 | 安全关闭或恢复一个无歧义的 prepared 事务 |
| `mnemo integration install/status/uninstall` | 仅宿主 Skill | 通过所有权检查管理轻量集成 |
| `mnemo handoff --input JSON --output FILE` | 否 | 打包用户选定的新会话交接信息 |

使用 `mnemo <command> --help` 查看全部参数。添加 `--json` 可输出供 Skills 和脚本使用的稳定响应封装。

### 退出码

| 代码 | 含义 |
|---:|---|
| `0` | 请求范围全部完成 |
| `2` | 安全部分已经完成，但仍有资产需要手动或条件式处理 |
| `3` | 存在冲突、批准不匹配或目标/包漂移；检查并重新生成计划 |
| `4` | 被本地安全策略拒绝 |
| `5` | 所需本地依赖或签名信任不可用 |
| `6` | 输入、包、Schema 或版本无效、不兼容或不受支持 |
| `70` | 未预期的内部错误 |

退出码 `2` 表示成功完成了安全子集，并不意味着可以把跳过项视为已经迁移。

## 产品路径与覆盖变量

MnemoPort 只读取 Adapter 批准的路径以及当前 workspace。隔离测试或非默认安装可以使用以下显式覆盖变量：

| 宿主 | 覆盖变量 | 默认用户路径 |
|---|---|---|
| Claude Code | `CLAUDE_CONFIG_DIR` | `~/.claude` |
| Codex | `CODEX_HOME` | `~/.codex`，外加当前 `~/.agents` Skills |
| Qoder | `QODER_CONFIG_DIR` | `~/.qoder` |
| Cursor | `CURSOR_AGENT_CONFIG_DIR`、`CURSOR_USER_DATA_DIR` | `~/.cursor`，外加所选平台的用户数据路径 |

覆盖变量只会选择根目录，不会扩大资产白名单。运行 `mnemo doctor --json` 和 `mnemo detect --json` 可以查看当前机器解析出的路径。产品行为与版本、操作系统和入口有关；例如 Cursor Agent 和 Cursor IDE 不会被视为同一个能力 tuple。

## 安全保证与限制

- 来源盘点和提取只读，绝不启动来源产品。
- `.mnemo` 内容具有确定性，使用 zstd 压缩、Ed25519 签名，并默认通过 age 加密。
- 路径、符号链接、归档大小、签名、哈希、对象闭包和目标前置条件都会被验证。
- Apply 使用已经同步到磁盘的本地备份、持久事务日志以及原子提交的 SQLite 事务/所有权更新，并为本地文件提供强回滚。
- 保留目标中无关的已有内容；冲突绝不被静默覆盖。
- 认证值、Cookies、系统钥匙串、内部数据库、信任决定和缓存均不迁移。
- 在 inventory、inspect、plan 和默认 L0 验证过程中，不执行脚本、Hooks、插件或 MCP Server。
- `--allow-plaintext` 仅用于用户明确确认不敏感的 fixture。真实个人资产不应使用该选项。

当前 Alpha 不会执行插件/扩展联网安装、CLI 依赖安装、OAuth/账号导出、MCP Server 执行、原生自动记忆导入或大范围编辑器 Profile 同步。只有在 Adapter 能够安全处理时，才会记录或盘点这些表面。prepared 与已提交但未确认事务的崩溃恢复、原子受管所有权、版本级探测，以及上文两个精确 tuple 的资产级 L1 配方都已实现；矩阵之外的原生能力仍明确降级为手动处理。发布制品和 provenance 声明只有在带 tag 的工作流成功后才成立。

## 故障排查

- **`mnemo: command not found`：** 把 Cargo 的二进制目录加入 `PATH`，然后重新打开终端。
- **加密包要求口令：** 在来源和目标上把 `MNEMOPORT_PASSPHRASE` 设置为同一个至少 12 字符的值。该值不会保存在包内。
- **退出码 2：** 检查 `skipped_assets` 和手动操作。安全子集已完成，但完整请求范围尚未完成。
- **签名者不受信任：** 运行 `inspect`，通过可信渠道核对显示的指纹，再运行 `mnemo trust add --input <package>`。
- **计划漂移或批准不匹配：** 丢弃当前计划，选择新的计划输出文件名，并针对当前目标重新运行 `plan`。
- **输出已经存在：** MnemoPort 不会覆盖包或计划文件，请选择新的输出路径。
- **集成卸载被拒绝：** 文件已被修改，或缺少 MnemoPort 所有权证据。请保留它，只有检查内容后才手动删除。
- **`doctor` 报告恢复候选项：** 运行 `recovery list`，检查哈希和 disposition，只明确回滚无歧义事务。保留 `manual-review` 目标用于调查。
- **需要详细本地诊断：** 去掉 `--json` 后重新运行；JSON 模式会有意输出稳定且经过清理的诊断信息。

安全问题和敏感数据处理方式参见 [`SECURITY.md`](SECURITY.md)。

## 开发与验证

在干净的 checkout 中运行：

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

CI 会在 Linux、macOS 和 Windows 上，分别使用 Rust 1.85 与 Stable 执行格式检查、Clippy 和完整测试套件，并另外运行 RustSec 与 `cargo-deny` 依赖策略任务。Fixture 测试提供核心 L0 证据，但不会把未经测试的原生产品版本、GUI、Remote 或 Cloud 入口升级为受支持状态。

## 文档

- [架构](docs/architecture.md)
- [兼容性与精确产品边界](docs/compatibility.md)
- [机器可读兼容性证据](docs/compatibility.json)
- [包格式](docs/package-format.md)
- [产品探测与证据边界](docs/product-probes.md)
- [发布与供应链安全](docs/release-security.md)
- [安全策略](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)

## 许可证

MnemoPort 使用 [MIT License](LICENSE)。

# SQLi Auditor

> 面向已授权 Web 目标的 SQL 注入检测与扫描栈工具（本机优先）。A local-first SQL injection detection and scanning-stack tool for web targets you are explicitly authorized to test.

SQLi Auditor 是一个用 Go 编写的应用安全审计工具，打包为单个可执行文件。它提供两层能力：**检测型审计**（低影响 quote 边界探测）与**完整扫描栈**（UNION 元数据发现 + 有界数据预览），网页默认监听 `127.0.0.1`，所有结果都标记为「启发式检测」。

SQLi Auditor is a Go-based application-security tool shipped as one executable. It offers two layers: a **detection-only audit** (low-impact quote-boundary probes) and a **full scanning stack** (UNION metadata discovery + bounded data preview). The web UI binds to `127.0.0.1` by default and every result is labelled as heuristic.

---

## 目录 / Table of Contents

- [功能特性 / Features](#功能特性--features)
- [技术栈 / Tech Stack](#技术栈--tech-stack)
- [界面说明 / Interface](#界面说明--interface)
- [安装要求 / Requirements](#安装要求--requirements)
- [Windows 一键启动 / Quick Start on Windows](#windows-一键启动--quick-start-on-windows)
- [CLI 使用示例 / CLI](#cli-使用示例--cli)
- [网页使用步骤 / Web Usage](#网页使用步骤--web-usage)
- [API 使用示例 / API](#api-使用示例--api)
- [配置参数说明 / Configuration](#配置参数说明--configuration)
- [请求预算与安全限制 / Limits & Safety](#请求预算与安全限制--limits--safety)
- [扫描原理 / How Detection Works](#扫描原理--how-detection-works)
- [SQL 扫描栈原理 / SQL Stack](#sql-扫描栈原理--sql-stack)
- [输出结果示例 / Example Output](#输出结果示例--example-output)
- [测试方法 / Testing](#测试方法--testing)
- [项目目录结构 / Repository Layout](#项目目录结构--repository-layout)
- [常见问题 / FAQ](#常见问题--faq)
- [合法使用声明 / Responsible Use](#合法使用声明--responsible-use)
- [贡献方式 / Contributing](#贡献方式--contributing)
- [安全漏洞报告 / Security](#安全漏洞报告--security)
- [MIT License 说明](#mit-license-说明)
- [中文说明](#中文说明)
- [English Documentation](#english-documentation)
- [相关项目 / Related Projects](#相关项目--related-projects)

---

## 功能特性 / Features

- 检测 URL 查询参数，判断哪些参数可能存在注入信号。
- 自动识别注入闭合方式（数字型 / 单引号 / 单引号+括号 / 双引号 / 双引号+括号）。
- 判断列数、判断可回显列。
- 检测数据库类型，至少支持 MySQL 兼容目标。
- 枚举数据库名称、指定数据库下的表、指定表的字段。
- 枚举阶段并发执行（可配置 1–16 并发），并复用 HTTP 长连接以显著提速。
- 当 UNION 回显不可用时，自动回退到**有界布尔盲注**推断当前数据库名。
- 对用户明确选择的表和字段执行**有限**数据预览（默认每表最多 5 行）。
- 逐阶段显示结果，可从网页重新发起扫描以重新执行流程。
- JSON 导出与 CLI 模式。
- 默认简体中文界面，可切换 English，切换时不产生布局跳动。
- 安全工程化：授权确认、请求预算、响应大小上限、Cookie 仅驻留内存、TLS 验证、禁止跨主机重定向、禁止时间延迟探测。

- Detects URL query parameters and flags those with a possible injection signal.
- Detects the injection closure (numeric / single-quote / single-quote + paren / double-quote / double-quote + paren).
- Determines column count and reflected columns.
- Detects database type (MySQL-compatible at minimum).
- Enumerates databases, tables per database, and columns per table.
- Runs enumeration stages concurrently (configurable 1–16 workers) and reuses HTTP keep-alive connections for a large speedup.
- Falls back to **bounded boolean-blind** inference of the current database name when UNION reflection is unavailable.
- Performs a **bounded** data preview (default max 5 rows per table) over user-selected tables/fields.
- Stage-by-stage results; re-run the scan from the UI to re-execute the flow.
- JSON export and a CLI mode.
- Simplified-Chinese UI by default with an English toggle that does not cause layout shift.
- Hardened: authorization confirmation, request budget, response-size cap, in-memory-only cookies, TLS verification, no cross-host redirects, no time-delay probes.

## 技术栈 / Tech Stack

- **Language**: Go 1.24+（仅标准库，无第三方运行时依赖）
- **Engine**: `net/http`, `net/url`, `crypto/sha256`, 正则表达式
- **Web UI**: 内嵌静态资源（`embed.FS`）+ 原生 HTML/CSS/JavaScript
- **Tests**: `net/http/httptest` 本地靶场模拟
- **CI**: GitHub Actions（`go test` / `go vet` / `go build`）

## 界面说明 / Interface

> 截图占位 / Screenshot placeholder — 运行后打开 `http://127.0.0.1:8812/` 即可看到深色安全仪表盘。

左侧为 8 个阶段的扫描栈（参数检测 / 注入类型 / 列数检测 / 回显列 / 数据库 / 表 / 字段 / 数据预览），每个阶段显示「等待中 / 运行中 / 已完成 / 部分完成 / 失败」；右侧为当前阶段结果。数据库、表、字段以分层卡片展示，数据预览使用表格并显示当前数据库、当前表、预览字段、预览行数与是否因请求预算而截断。

## 安装要求 / Requirements

- Go 1.24 或更高版本。
- 无需数据库、无需第三方依赖。

## Windows 一键启动 / Quick Start on Windows

1. 双击 `start.cmd`。
2. 若浏览器未自动打开，访问 `http://127.0.0.1:8812/`。
3. 输入一个含查询参数的已授权 URL，例如本地靶场 `http://127.0.0.1:8080/item?id=1`。
4. 输入授权确认短语 `我已获得授权`（或 `I HAVE AUTHORIZATION`），点击「开始授权扫描」。

使用 `build-release.cmd` 构建独立可执行文件，输出到 `dist/`。

## CLI 使用示例 / CLI

```powershell
# 检测型审计（仅 quote 边界探测）
go run -buildvcs=false . audit -target "http://127.0.0.1:8080/item?id=1" -delay 150 -authorized

# 完整扫描栈（UNION 元数据发现 + 有限数据预览）
go run -buildvcs=false . stack -target "http://127.0.0.1:8080/item?id=1" -budget 120 -rows 3 -conc 8 -authorized
```

`-authorized` 是强制参数，未显式确认授权时程序会拒绝执行。

## 网页使用步骤 / Web Usage

1. 双击 `start.cmd`，打开 `http://127.0.0.1:8812/`。
2. 填写目标 URL（必须含查询参数，例如 `?id=1`）。
3. （可选）填写会话 Cookie，仅用于本次请求且不会出现在报告中。
4. 设置请求间隔、请求预算与预览行数。
5. 输入授权确认短语，点击「开始授权扫描」。
6. 左侧扫描栈逐步更新状态，右侧展示参数、数据库、表、字段与数据预览。
7. 点击「导出 JSON」下载报告。

## API 使用示例 / API

```http
GET /api/config
# { "token": "...", "max_parameters": 5, "default_request_budget": 120, "max_request_budget": 240, "max_preview_rows": 5, "default_concurrency": 8, "max_concurrency": 16 }
```

```http
POST /api/audit
Content-Type: application/json
X-Auditor-Token: <token>

{ "target": "http://127.0.0.1:8080/item?id=1", "cookie": "", "confirmation": "我已获得授权", "delay_ms": 150 }
```

```http
POST /api/stack
Content-Type: application/json
X-Auditor-Token: <token>

{
  "target": "http://127.0.0.1:8080/item?id=1",
  "cookie": "",
  "confirmation": "I HAVE AUTHORIZATION",
  "delay_ms": 150,
  "request_budget": 120,
  "preview_rows": 3,
  "concurrency": 8
}
```

`/api/stack` 返回结构：

```json
{
  "schema": "sqli-auditor-stack/1.0",
  "target": "http://127.0.0.1:8080/item?id=REDACTED",
  "dbms": "MySQL-compatible",
  "requests": 20,
  "request_budget": 120,
  "partial": false,
  "parameters": [],
  "stages": [],
  "databases": [],
  "notes": []
}
```

## 配置参数说明 / Configuration

| 参数 | 默认值 | 范围 | 说明 |
| --- | --- | --- | --- |
| `target` | — | http/https URL | 含查询参数的授权目标 |
| `cookie` | 空 | 字符串 | 仅驻留内存，绝不出现在报告 |
| `confirmation` | — | `我已获得授权` / `I HAVE AUTHORIZATION` | 授权确认短语 |
| `delay_ms` | `150` | 0–2000 | 请求之间的间隔 |
| `request_budget` | `120` | 20–240 | 单次扫描最大请求数 |
| `preview_rows` | `3` | 0–5 | 每表最多预览行数 |
| `concurrency` | `8` | 1–16 | 枚举阶段并发请求数 |

## 请求预算与安全限制 / Limits & Safety

- 每次扫描设置最大请求数（`request_budget`），达到上限即标记「部分完成」。
- 最大数据库数 6、最大表数 8、最大字段数 16、最大预览行数 5。
- 默认只显示有限数据预览，禁止无界导出。
- 请求超时、响应大小（1 MiB）、总执行时间均有上限。
- 目标 URL 在结果中脱敏查询参数值。
- Cookie 只在内存中使用，不写入日志、报告或错误信息。
- 默认启用 TLS 证书验证，默认禁止跨主机重定向。
- 禁止时间延迟探测、禁止无界 `GROUP_CONCAT`、禁止无限 `LIMIT` 循环。
- 数据库名、表名、字段名经过严格标识符校验，防止二次 SQL 注入。
- 查询结果中的 HTML 一律按纯文本处理。
- 结果标记为「启发式检测」，不声称百分百确认漏洞。

## 扫描原理 / How Detection Works

检测型审计会先抓取两次基线以识别动态页面，再对每个查询参数发送一次 quote 边界探测（追加 `'`）。仅当出现稳定的响应变化或「仅在探测后才出现」的数据库错误签名（MySQL / PostgreSQL / SQL Server / Oracle / SQLite）时才报告发现。基线不稳定时，仅凭响应长度差异的发现会被抑制，以降低误报。

## SQL 扫描栈原理 / SQL Stack

完整扫描栈按固定顺序执行以下 8 个阶段，每一步都受请求预算约束：

1. **参数检测** — 枚举查询参数，用 quote 边界探测判断是否存在注入信号。
2. **注入类型** — 依次探测五种闭合方式（数字型、单引号、单引号+括号、双引号、双引号+括号），用布尔真/假表达式（`AND 1=1` vs `AND 1=2`）判定有效的闭合上下文，后续所有载荷都套用该闭合。
3. **列数检测** — 用 `ORDER BY n` 逐列递增，出现错误即确定列数。
4. **回显列** — 用 `UNION SELECT` 注入带标记的常量，找出可回显列；若 UNION 回显不可用，回退到**有界布尔盲注**（`LENGTH` + `ORD`/`SUBSTRING` 二分）推断当前数据库名。
5. **数据库** — 查询 `information_schema.schemata`，并将 `database()` 当前库置顶优先枚举，避免核心库被字母序跳过。
6. **表** — 查询 `information_schema.tables`，按 `table_schema` 过滤，并发执行。
7. **字段** — 查询 `information_schema.columns`，按库与表过滤，并发执行。
8. **数据预览** — 对用户选择（默认前 6 列）的字段执行有界 `LIMIT offset,1` 预览，跨表与行并发执行。

所有枚举使用唯一标记（marker）包裹、`GROUP_CONCAT` 聚合并用分隔符拆分；标识符经严格校验并反引号转义；提取结果会剥离 HTML 标签并按纯文本展示。

## 输出结果示例 / Example Output

```json
{
  "schema": "sqli-auditor-stack/1.0",
  "target": "http://127.0.0.1:8080/item?id=REDACTED",
  "dbms": "MySQL-compatible",
  "requests": 18,
  "request_budget": 120,
  "duration_ms": 230,
  "partial": false,
  "parameters": [
    { "name": "id", "injectable": true, "injection_type": "string", "column_count": 3, "display_columns": [0, 1, 2], "evidence": "database error signature: MySQL" }
  ],
  "stages": [
    { "key": "parameter_detection", "status": "complete", "requests": 2 },
    { "key": "injection_type", "status": "complete", "requests": 4 },
    { "key": "column_count", "status": "complete", "requests": 4 },
    { "key": "display_columns", "status": "complete", "requests": 1 },
    { "key": "databases", "status": "complete", "requests": 1 },
    { "key": "tables", "status": "complete", "requests": 1 },
    { "key": "fields", "status": "complete", "requests": 1 },
    { "key": "data_preview", "status": "complete", "requests": 3 }
  ],
  "databases": [
    { "name": "appdb", "tables": [ { "name": "users", "columns": ["id", "username"], "rows": [ { "id": "1", "username": "admin" } ] } ] }
  ],
  "notes": ["Full-stack mode uses UNION-based metadata discovery and bounded data previews.", "Findings are heuristic and require manual confirmation; they are not proof of a vulnerability."]
}
```

## 测试方法 / Testing

```powershell
go test -buildvcs=false ./...
go vet -buildvcs=false ./...
go build -buildvcs=false ./...
```

测试覆盖：SQL 扫描栈全流程、本地 `httptest` 模拟 MySQL 错误响应、列数检测、数据库/表/字段返回、有限数据预览、请求预算耗尽、布尔盲注回退推断、并发数校验、授权确认失败、空结果、动态页面抗误报、Cookie 不出现在报告、以及中英文切换逻辑静态检查。

本地 mock 目标按 sqli-labs 的真实行为建模：SQL 报错以 HTTP 200 反射在页面正文（而非 500），且 UNION 行仅在首 SELECT 被取反（`AND 1=2`）时才回显。mock 同时覆盖三种闭合（Less-1 单引号、Less-2 数字型、Less-3 单引号+括号）。扫描栈已针对 `http://sqlilabs.njhack.xyz/Less-1/?id=1`、`Less-2/?id=1`、`Less-3/?id=1` 训练靶场做端到端验证，可枚举 `security` 库下的 `emails`、`users` 等表并做有界数据预览。

## 项目目录结构 / Repository Layout

```text
internal/audit/       检测引擎（audit.go）与扫描栈（stack.go）及单元测试
web/                  内嵌网页控制台（index.html / app.js / i18n.js / style.css）
design-system/        UI 设计规则
.github/workflows/    持续集成
start.cmd             Windows 一键启动
build-release.cmd     构建独立可执行文件
```

## 常见问题 / FAQ

- **为什么显示「部分完成」？** 请求预算达到上限，枚举或预览被截断。可提高 `request_budget`（≤240）后重新扫描。
- **为什么未检测到注入？** 可能是目标参数不可注入、存在 WAF，或 Cookie 已过期。结果仅供启发式参考，不代表目标绝对安全。
- **支持哪些数据库？** 至少支持 MySQL 兼容目标；错误签名也能识别 PostgreSQL / SQL Server / Oracle / SQLite。
- **Cookie 会被记录吗？** 不会。Cookie 仅驻留内存，绝不写入日志、报告或错误信息。
- **能导出无限数据吗？** 不能。数据预览受行数与请求预算双重限制。

## 合法使用声明 / Responsible Use

SQLi Auditor 仅用于你拥有或已获得明确书面授权的系统。禁止未授权扫描、绕过认证、凭证攻击、漏洞利用链、持久化或未授权批量扫描。使用者对自身行为承担全部法律责任。

## 贡献方式 / Contributing

见 [CONTRIBUTING.md](CONTRIBUTING.md)。核心原则：保持请求预算、脱敏、TLS 验证、本机监听与授权确认不变；schema 枚举与数据提取仅限有界、授权场景；认证绕过、破坏性载荷、时间攻击与规避特性不在项目范围内。

## 安全漏洞报告 / Security

请通过私有 GitHub 安全通告报告漏洞，见 [SECURITY.md](SECURITY.md)。报告中请移除 Cookie、凭证、私密 URL 与响应内容。

## MIT License 说明

本项目采用 [MIT License](LICENSE)，© 2026 C-8H11N。你可以自由使用、修改与分发，但需保留版权与许可声明，且软件按「原样」提供，不附带任何担保。

---

## 中文说明

SQLi Auditor 是仅用于授权目标的应用安全审计工具，双击 `start.cmd` 启动，默认监听 `127.0.0.1:8812`。它提供检测型审计与完整扫描栈两种模式，逐阶段展示结果，数据库、表、字段与有限数据预览可分层查看。所有结果属于启发式证据，需要人工复核，且不声称百分百确认漏洞。请勿用于未获许可的系统。

## English Documentation

SQLi Auditor is an authorized-use application-security tool. Double-click `start.cmd` to launch it; it listens on `127.0.0.1:8812` by default. It offers a detection-only audit and a full scanning stack with stage-by-stage results, hierarchical database/table/field cards, and bounded data preview. All results are heuristic evidence requiring manual confirmation and are never presented as proof of a vulnerability. Do not use it against systems you are not permitted to assess.

## 相关项目 / Related Projects

- [PortScope](../portscope) — 同系列的授权型 TCP 连接扫描器。
- 原始参考实现位于 `../自制sql注入/sqli_tool`（历史参考，已由本 Go 项目取代）。

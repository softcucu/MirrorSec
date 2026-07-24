# MirrorSec

MirrorSec（镜鉴）用于从 Git 历史提交中识别已经修复的安全问题，并以这些历史问题为依据，在当前代码中继续排查同类漏洞。

主程序会同时运行两条任务：

1. Git 历史审计：分析提交及其修复前代码，将确认的历史安全问题写入 SQLite。
2. 同类问题排查：持续从同一个 SQLite 数据库领取尚未排查的历史问题，先发现候选位置，再并发审计候选点，并保存确认的漏洞。

同类问题排查只有在数据库中存在未成功排查的历史问题时才会调用模型。历史审计运行期间新写入的问题也会在本次运行中继续被领取。

## 运行环境

需要准备：

- Python 3.12 或更高版本。
- Git。
- 可用的 `opencode` 或 `nga` Serve 命令。
- 已配置模型的 Task Agent YAML。

安装 Task Agent 依赖：

```bash
python3 -m pip install -e ./task_agent
```

## 配置 Task Agent

复制示例配置：

```bash
cp task_agent/task-agent.example.yaml task-agent.yaml
```

编辑 `task-agent.yaml`，至少确认以下内容：

- `context.project_dir`、`context.work_dir` 和 `context.workspace_dir` 是有效的绝对路径。主程序运行时会把实际审计项目覆盖为 `--repo` 指定的仓库。
- `serve.executable` 指向可执行的 `opencode` 或 `nga`。
- `model_pool.models` 中存在满足能力要求且已启用的模型。
- 默认历史审计需要 `medium` 或更高能力模型。
- 默认同类问题排查需要 `high` 能力模型。

一个 `high` 能力模型同时满足 `medium` 和 `high` 的最低能力要求。实际并发还会受到 `model_pool.global_concurrency` 和每个模型 `max_concurrency` 的限制。

配置文件也可以放在其它位置，通过 `--config-path` 指定：

```bash
python3 main.py \
  --repo /absolute/path/to/repository \
  --config-path /absolute/path/to/task-agent.yaml
```

也可以设置环境变量：

```bash
export TASK_AGENT_CONFIG=/absolute/path/to/task-agent.yaml
python3 main.py --repo /absolute/path/to/repository
```

## 快速运行

最小运行命令：

```bash
python3 main.py \
  --repo /absolute/path/to/repository \
  --config-path ./task-agent.yaml
```

完整示例：

```bash
python3 main.py \
  --repo /absolute/path/to/repository \
  --db /absolute/path/to/mirrorsec.sqlite3 \
  --history-concurrency 4 \
  --history-capability medium \
  --similar-concurrency 8 \
  --similar-capability high \
  --revision-range HEAD \
  --config-path /absolute/path/to/task-agent.yaml
```

查看全部命令行参数：

```bash
python3 main.py --help
```

## Web 看板

Web 看板是独立的只读进程，不会启动、停止或修改审计任务。分析任务运行时，
另开一个终端并让看板读取同一个 SQLite 文件：

```bash
python3 web_dashboard.py \
  --db /absolute/path/to/mirrorsec.sqlite3
```

浏览器访问：

```text
http://127.0.0.1:8765
```

页面首次打开时读取数据，之后可点击右上角的“立即刷新”获取最新内容。看板包含
两个表格页签：

- `Git 历史问题`：显示 `vulnerabilities` 中从历史修复提交确认的问题。
- `问题排查结果`：显示 `similar_issue_findings` 中在当前代码确认的同类问题。

看板支持关键词搜索、严重性筛选、分页和完整详情查看。数据库尚未创建或任务
暂未写入结果时，页面会保持等待状态；任务写入结果后可手动刷新查看。

自定义监听地址和端口：

```bash
python3 web_dashboard.py \
  --db /absolute/path/to/mirrorsec.sqlite3 \
  --host 0.0.0.0 \
  --port 9000
```

看板没有内置身份认证。使用 `0.0.0.0` 对外提供访问时，应通过防火墙或反向
代理限制访问范围。

## 命令行参数

| 参数 | 是否必填/默认值 | 说明 |
| --- | --- | --- |
| `--repo` | 必填 | 待审计 Git 代码仓路径，必须是有效的 Git 仓库。 |
| `--db` | `git_history_analysis.sqlite3` | SQLite 数据库路径。历史审计产物、同类问题排查状态和确认漏洞都存入该数据库。 |
| `--history-concurrency` | `4` | 同时分析的 Git commit 数量。 |
| `--history-capability` | `medium` | Git 历史审计要求的最低模型能力，可选 `low`、`medium`、`high`。 |
| `--similar-concurrency` | `4` | 同类问题排查的全局模型任务并发上限，覆盖所有历史问题的候选发现和候选点审计。 |
| `--similar-capability` | `high` | 同类问题排查要求的最低模型能力，可选 `low`、`medium`、`high`。 |
| `--revision-range` | `HEAD` | 传给 Git 历史审计的 revision range。 |
| `--config-path` | 自动发现 | Task Agent YAML 路径。未指定时依次读取 `TASK_AGENT_CONFIG` 和当前目录的 `task-agent.yaml`。 |

历史审计会逐条读取 commit，并且任何时刻最多只保留
`--history-concurrency` 个处理任务；不会为整个仓库一次性创建任务。
超大仓库如需严格逐个处理，可设置 `--history-concurrency 1`。

例如：

```bash
--similar-concurrency 8
```

表示所有同类问题排查任务合计最多同时执行 8 个模型调用。即使数据库中同时存在多个待排查历史问题，它们的候选发现和候选审计也共享这个全局上限。

## 运行进度

程序只打印关键进展，典型输出如下：

```text
[main] START repo=/code/project db=/data/mirrorsec.sqlite3 history_capability=medium similar_capability=high
[history] START repo=/code/project concurrency=4
[similar] START issue=2f37d93a84ab#1
[similar] DONE issue=2f37d93a84ab#1 findings=2
[history] DONE analyzed=120 failed=0 issues_saved=6
[similar] DONE scheduled=6 completed=6 failed=0 findings_saved=3
[main] DONE
```

单个同类问题排查失败不会被标记为完成。失败和程序中断的任务会在下次运行时重试。

## 数据库产物

`--db` 指定的同一个 SQLite 文件包含以下主要表：

| 表名 | 内容 |
| --- | --- |
| `analyzed_commits` | Git commit 的历史审计状态、元数据和模型原始结果。 |
| `vulnerabilities` | 从历史修复提交中确认的安全问题，包括漏洞描述、漏洞根因和修复前代码。 |
| `similar_issue_audits` | 每个历史问题针对目标代码仓的同类问题排查状态、执行次数和结果数量。 |
| `similar_issue_findings` | 同类问题排查最终确认的漏洞及其代码位置、根因、证据、攻击路径、严重性和修复建议。 |

查看历史问题：

```bash
sqlite3 /absolute/path/to/mirrorsec.sqlite3 \
  "SELECT commit_hash, issue_number, description FROM vulnerabilities;"
```

查看确认的同类漏洞：

```bash
sqlite3 /absolute/path/to/mirrorsec.sqlite3 \
  "SELECT code_location, severity, title FROM similar_issue_findings;"
```

查看同类问题排查状态：

```bash
sqlite3 /absolute/path/to/mirrorsec.sqlite3 \
  "SELECT source_commit_hash, source_issue_number, status, findings_count, error FROM similar_issue_audits;"
```

## 单独调用同类问题排查接口

如需从其它异步 Python 程序中调用：

```python
from find_similar_issue import run_similar_issues_audit

findings = await run_similar_issues_audit(
    issue_description="漏洞描述",
    issue_root_analysis="漏洞根因",
    issue_code="修复前的漏洞代码片段",
    code_path="/absolute/path/to/repository",
)
```

该接口返回确认存在的同类漏洞列表。每个结果包含代码位置、严重性、标题、根因、证据、攻击路径、相似性分析、差异分析、修复建议和置信度。

单独调用该接口时，Task Agent 的 `context.project_dir` 必须指向包含 `code_path` 的项目目录；由 `main.py` 启动时会自动绑定为 `--repo` 指定的仓库。

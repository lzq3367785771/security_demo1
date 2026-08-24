# 网络安全自动化智能运维系统 (AI Agent SOC & SOAR Demo)

本项目是一个基于大语言模型 (LLM) 和 AI Agent 技术构建的网络安全自动化运维演示原型。系统模拟了从底层数据采集、Agent 智能研判、合规校验到 SOAR 自动化编排的完整安全防护闭环。

## 💡 核心设计思路与算法实现

本项目抛弃了传统的“规则匹配”告警模式，采用**“大模型驱动的安全智能体 (Security Agent)”**作为核心大脑，实现了以下关键逻辑：

1. **动态日志流注入与模拟**：
   - 抛弃静态全量加载，采用 `mock_stream.py` 在后台模拟真实设备的流式数据输出（JSONL 格式）。
   - 包含针对常见攻击（SQL 注入、异常登录、端口扫描等）的原始底层报文（`raw_payload`），用于测试 AI 的深度解析能力。

2. **Agent 核心大脑 (Function Calling)**：
   - **报文翻译**：利用大模型将十六进制、SQL 语法等生涩的底层特征，翻译成结构化的威胁情报（IoC、攻击定性、影响评估）。
   - **自主决策**：通过 OpenAI 兼容 API 的 `tools` (Function Calling) 机制，Agent 在分析后自动生成调度意图，强制下发对应的剧本调度指令，实现思维到行动的闭环。

3. **SOAR 自动化编排与防误封机制**：
   - **路由分发**：在 `action.py` 中实现了根据威胁等级动态路由到不同剧本（`playbook_low_risk`, `playbook_high_risk` 等）。
   - **合规校验层**：在执行任何封禁前，系统会强制进行 `WHITELIST_IPS`（白名单）前置校验。当 Agent 试图封禁网关或核心 DNS（如 8.8.8.8）时，系统底层将拦截该指令，避免“自杀式防御”。

4. **交互式数据可视化**：
   - 基于 Streamlit 构建轻量级前端。提供实时态势大盘、动态告警流转以及基于 Pandas DataFrame 的高交互审计日志记录。

## 📂 目录结构

```text
security_demo/
├── app.py                 # Streamlit 前端主程序与交互逻辑
├── mock_stream.py         # 动态安全日志生成器 (模拟底层探针)
├── config/
│   └── config.py          # 配置文件 (API Key 及大模型 URL)
├── data/
│   ├── audit.json         # 自动化操作的安全审计记录库
│   ├── devices.json       # 安全设备状态台账
│   └── dynamic_logs.jsonl # 动态流式安全告警数据
├── modules/
│   ├── ai.py              # Agent 研判大脑 (大模型 API 交互)
│   ├── action.py          # SOAR 剧本库与合规校验路由中心
│   ├── alarm.py           # 告警数据读取与处理模块
│   ├── audit.py           # 审计日志保存模块
│   └── device.py          # 设备状态读取模块
└── README.md
🛠️ 环境依赖与配置
Python 环境：建议使用 Python 3.8 或以上版本。

安装依赖包：
在 VS Code 终端 (PowerShell) 中执行以下命令安装必要依赖：

PowerShell
pip install streamlit pandas openai
配置大模型 API：
打开 config/config.py，填入您所使用的大模型 API 密钥。目前代码默认使用的是 deepseek-v4-flash 模型，如果使用其他模型（如 Qwen），请同步修改 modules/ai.py 中的 model 参数。

🚀 启动与使用指南 (Windows + VS Code)
本项目采用前后端解耦的数据流模式，需要同时运行日志注入脚本和前端页面。推荐利用 VS Code 的“拆分终端”功能：

步骤 1：启动后台日志模拟流

在 VS Code 中打开新建一个终端。

运行以下命令，系统将开始每隔几秒随机生成攻击日志：

PowerShell
python mock_stream.py
(该进程请保持在后台运行，不要关闭)

步骤 2：启动可视化平台

在 VS Code 终端面板点击右上角的 “拆分终端” 按钮（或按 Ctrl + Shift + 5）。

在新的终端窗口中，运行 Web 服务：

PowerShell
streamlit run app.py
浏览器将自动弹出控制台页面（默认地址 http://localhost:8501）。

步骤 3：体验 Agent 闭环

在页面上方的“安全告警中心”中，展开任意一条告警。

点击 “🤖 Agent 自主研判与处置” 按钮。

观察 Agent 是如何解析生涩报文、制定防御剧本，并在命中“核心资产”时被底层合规机制拦截退回的。

在页面底部的“安全审计记录”表中，可以按处理状态（如“校验拦截”或“执行成功”）动态过滤查看 Agent 的历史操作。

🔮 后续演进路线
本 Demo 为后续接入真实网络环境奠定了架构基础。下一步可演进方向包括：

真实设备接入：将 mock_stream.py 替换为 Elasticsearch / Logstash / Syslog 探针接口，直连真实网关。

SOAR 动作实体化：将 action.py 中的占位符升级为真实的 REST API 调用（如对接防火墙的阻断接口）。

多智能体 (Multi-Agent)：引入 LangGraph 框架，将单一研判 Agent 拆分为数据清洗 Agent、研判 Agent 和 审批 Agent 的协作网络。
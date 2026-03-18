# IDAssist

*AI-Powered Reverse Engineering Plugin for IDA Pro*

**Author:** Jason Tang

## Description

IDAssist is an IDA Pro plugin that integrates LLM-powered analysis directly into IDA's interface, providing AI-assisted binary reverse engineering through configurable LLM providers, semantic knowledge graphs, RAG document search, and supports a wide diversity of LLM providers.

Built with Python and PySide6, IDAssist runs as a dockable panel inside IDA Pro 9.0+ and communicates with LLM providers (OpenAI, Anthropic, Ollama, LiteLLM, and more) to analyze functions, suggest renames, answer questions about code, and build a searchable knowledge graph of an entire binary.

<!-- SCREENSHOT: IDAssist main interface showing the Explain tab with a function explanation and security analysis panel -->
![Screenshot](/docs/screenshots/slideshow.gif)

## Core Features

**Function Explanation** — Generate detailed natural-language explanations of decompiled functions with automatic security analysis including risk level, activity profile, security flags, and API detection.

**Interactive Query Chat** — Ask questions about the binary with persistent chat history. Use context macros (`#func`, `#addr`, `#line`, `#range`) to inject function code, addresses, or disassembly ranges into queries.

**Automated Actions** — AI-powered rename suggestions for functions, variables, and types. Review proposed changes in a table with confidence scores, then apply selected actions back to the IDB.

**Semantic Knowledge Graph** — Build and explore a knowledge graph of the binary's functions, call relationships, data flows, and security characteristics. Includes visual graph rendering, semantic search, and community detection.

**RAG Document Search** — Upload reference documents (`.txt`, `.md`, `.rst`, `.pdf`) and use them as context during LLM queries. Supports hybrid text+vector search via Whoosh indexing.

**SymGraph Integration** — Push and pull function names, variable names, types, and graph data to the SymGraph collaborative platform. Includes a multi-step wizard with conflict resolution for pulls.

**Settings Management** — Configure multiple LLM and MCP providers, manage SymGraph API credentials, customize the system prompt, and set database paths.

## Advanced Capabilities

### ReAct Agent

The Query tab supports an autonomous ReAct (Reasoning + Acting) agent mode. When enabled, the LLM plans an investigation strategy, executes tools to gather information, reflects on findings, and synthesizes a comprehensive answer — all automatically across multiple reasoning rounds.

### Extended Thinking

Configure reasoning effort levels to control how much the LLM "thinks" before responding:

| Level | Thinking Budget | Best For |
|-------|----------------|----------|
| None | Disabled | Fast, simple queries |
| Low | ~2K tokens | Straightforward analysis |
| Medium | ~10K tokens | Moderate complexity |
| High | ~25K tokens | Deep analysis, complex code |

### MCP Integration

IDAssist can connect to external MCP servers for tool-augmented LLM interactions where the model can programmatically inspect functions, read disassembly, query cross-references, and modify the IDB during reasoning. IDAssist also provides built-in internal tools for function calling without requiring an external MCP server.

### Function Calling

LLM providers with tool-calling support can invoke IDA analysis functions mid-conversation, enabling iterative investigation without manual intervention.

### RLHF Feedback

Provide thumbs-up/thumbs-down feedback on explanations and query responses. Feedback is stored locally and can be used to improve prompt engineering and model selection.

## Architecture

IDAssist follows an MVC (Model-View-Controller) pattern:

- **Views** (`src/views/`) — PySide6 tab widgets that emit signals on user interaction
- **Controllers** (`src/controllers/`) — Connect view signals to service calls, manage state
- **Services** (`src/services/`) — Business logic, LLM providers, database access, graph analysis
- **Internal Tools** (`src/services/internal_tools.py`) — IDA-specific tool definitions for LLM function calling
- **Graph Tools** (`src/services/graphrag/graphrag_tools.py`) — Semantic graph read/write tools for LLM interaction

Key design principles:
- All IDA API calls execute on the main thread via `execute_on_main_thread()`
- LLM responses stream incrementally to the UI
- Local SQLite databases for persistence (no external database required)
- Singleton service registry with thread-safe initialization

## Quick Start

1. **Install the plugin** (recommended — IDA Plugin Manager):

   ```
   hcli plugin install idassist
   ```

   This automatically installs the plugin and its Python dependencies into IDA's environment.

2. **Or install manually** (from release tarball):

   Download the latest release zip from [GitHub Releases](https://github.com/jtang613/IDAssist/releases) and extract it into your IDA plugins directory:

   **Linux / macOS:**
   ```bash
   unzip IDAssist-*.zip -d ~/.idapro/plugins/
   ```

   **Windows:**
   Extract the zip into `%APPDATA%\Hex-Rays\IDA Pro\plugins\`.

   Then install dependencies using **IDA's bundled Python** (not your system Python):

   **Linux / macOS:**
   ```bash
   <IDA_INSTALL_DIR>/python3/bin/pip3 install -r ~/.idapro/plugins/IDAssist/requirements.txt
   ```

   **Windows:**
   ```cmd
   "<IDA_INSTALL_DIR>\python3\python.exe" -m pip install -r "%APPDATA%\Hex-Rays\IDA Pro\plugins\IDAssist\requirements.txt"
   ```

   > Replace `<IDA_INSTALL_DIR>` with your IDA Pro installation path (e.g., `/opt/idapro-9.0` or `C:\Program Files\IDA Pro 9.0`).
   >
   > **Tip:** You can also set the `IDAUSR` environment variable to a custom directory containing a `plugins/` subdirectory.

3. **Open IDAssist:** Launch IDA Pro, open a binary, and press `Ctrl+Shift+A` (or Edit > Plugins > IDAssist).

4. **Configure a provider:** Go to the Settings tab, click **Add** under LLM Providers, and configure your preferred provider.

5. **Analyze a function:** Navigate to any function, click the **Explain** tab, and press **Explain Function**.

For detailed setup instructions, see [Getting Started](docs/getting-started.md).

## LLM Provider Setup

IDAssist supports the following provider types:

| Type | Auth Method | Notes |
|------|-------------|-------|
| `anthropic_platform` | API Key | Anthropic API direct |
| `anthropic_oauth` | OAuth (browser) | Browser-based authentication |
| `anthropic_claude_cli` | Local CLI | Uses the `claude` CLI binary |
| `openai_platform` | API Key | OpenAI API direct |
| `openai_oauth` | OAuth (browser) | Browser-based authentication |
| `ollama` | None (local) | Self-hosted models |
| `litellm` | Proxy URL | Multi-provider proxy |

### Recommended Models

| Provider | Model | Strengths |
|----------|-------|-----------|
| Anthropic | `claude-sonnet-4-6` | Strong code analysis, extended thinking |
| OpenAI | `gpt-5.3-codex` | Fast, good general analysis |
| Ollama | `qwen2.5-coder:32b` | Local, no API key needed |

## Using the Semantic Graph

The Semantic Graph tab provides a knowledge graph of the binary:

1. **ReIndex Binary** — Extracts function structure, call graph, and cross-references
2. **Semantic Analysis** — Generates LLM summaries for each function
3. **Security Analysis** — Detects vulnerability patterns and security-relevant APIs
4. **Network Flow** — Tracks network operations across the call graph
5. **Community Detection** — Groups related functions into modules

Explore the graph via the **List View** (callers, callees, edges, flags), **Visual Graph** (interactive node diagram with N-hop expansion), or **Search** (7 query types including semantic search, similar functions, and call context).

## Context Menu Actions

Right-click in any Disassembly or Pseudocode view to access:

| Action | Hotkey | Effect |
|--------|--------|--------|
| Explain Function | `Ctrl+Shift+E` | Opens Explain tab and generates explanation |
| Ask About Selection | `Ctrl+Shift+Q` | Opens Query tab with `#func` context |
| Rename Suggestions | — | Opens Actions tab and generates suggestions |

## Requirements

- **IDA Pro 9.0+** with Python 3 and PySide6
- **Hex-Rays Decompiler** (recommended for pseudocode features)
- Python packages listed in `requirements.txt`

## Documentation

- [Documentation Index](docs/index.md)
- [Getting Started](docs/getting-started.md)
- Tab References: [Explain](docs/tabs/explain-tab.md) | [Query](docs/tabs/query-tab.md) | [Actions](docs/tabs/actions-tab.md) | [Semantic Graph](docs/tabs/semantic-graph-tab.md) | [RAG](docs/tabs/rag-tab.md) | [Settings](docs/tabs/settings-tab.md)
- Workflows: [Explain](docs/workflows/explain-workflow.md) | [Query](docs/workflows/query-workflow.md) | [Semantic Graph](docs/workflows/semantic-graph-workflow.md)

## Homepage

[https://symgraph.ai](https://symgraph.ai)

## License

See LICENSE file for details.

# Getting Started with IDAssist

This guide walks you through installing IDAssist, configuring an LLM provider, and running your first function analysis.

## Prerequisites

- **IDA Pro 9.0+** with Python 3 support
- **Hex-Rays Decompiler** (recommended — enables pseudocode features)
- **Python 3.11+** (bundled with IDA Pro 9.x)
- **pip** for installing Python dependencies (manual installation only)

## Installation

### Step 1: Install the Plugin

**Option A: IDA Plugin Manager** (recommended)

```
hcli plugin install idassist
```

This automatically installs the plugin and its Python dependencies into IDA's environment. No further steps are needed — skip ahead to [Step 2: Verify Installation](#step-2-verify-installation).

**Option B: Manual install** (from release zip)

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

### Step 2: Verify Installation

1. Launch IDA Pro and open any binary
2. Check the Output window for: `IDAssist: Plugin initialized`
3. The IDAssist panel should appear as a dockable tab

If the panel doesn't appear automatically, press **Ctrl+Shift+A** or go to **Edit > Plugins > IDAssist**.

## Open IDAssist

- **Hotkey:** `Ctrl+Shift+A`
- **Menu:** Edit > Plugins > IDAssist
- IDAssist opens as a dockable panel that persists across IDA sessions

## Configuring an LLM Provider

Navigate to the **Settings** tab to configure your LLM provider. IDAssist needs at least one configured provider before it can analyze functions.

### Option 1: Ollama (Local, Free)

Best for getting started quickly with no API keys.

1. Install Ollama from [ollama.com](https://ollama.com)
2. Pull a model: `ollama pull qwen2.5-coder:32b`
3. In IDAssist Settings, click **Add** under LLM Providers:
   - **Name:** `Ollama`
   - **Type:** `ollama`
   - **Model:** `qwen2.5-coder:32b`
   - **URL:** `http://localhost:11434`
   - **API Key:** (leave blank)
4. Click **Save**, then set as **Active Provider**

### Option 2: OpenAI

1. Get an API key from [platform.openai.com](https://platform.openai.com)
2. In IDAssist Settings, click **Add**:
   - **Name:** `OpenAI`
   - **Type:** `openai_platform`
   - **Model:** `gpt-4o`
   - **URL:** `https://api.openai.com/v1`
   - **API Key:** your key
3. Click **Save**, then set as **Active Provider**

### Option 3: Anthropic

1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. In IDAssist Settings, click **Add**:
   - **Name:** `Claude`
   - **Type:** `anthropic_platform`
   - **Model:** `claude-sonnet-4-6`
   - **URL:** `https://api.anthropic.com`
   - **API Key:** your key
3. Click **Save**, then set as **Active Provider**

### Option 4: LiteLLM Proxy

Use LiteLLM to route through multiple providers with a single endpoint.

1. Set up a LiteLLM proxy server
2. In IDAssist Settings, click **Add**:
   - **Name:** `LiteLLM`
   - **Type:** `litellm`
   - **Model:** your model name
   - **URL:** your proxy URL
   - **API Key:** your proxy key (if required)
3. Click **Save**, then set as **Active Provider**

### Option 5: AWS Bedrock

Use AWS Bedrock Converse API directly via boto3. Requires an AWS account with Bedrock access.

1. Ensure you have **AWS credentials** configured (env vars, `~/.aws/credentials`, or IAM role)
2. In IDAssist Settings, click **Add**:
   - **Name:** `AWS Bedrock`
   - **Type:** `bedrock`
   - **Model:** e.g., `anthropic.claude-sonnet-4-6`
   - **AWS Region:** e.g., `us-east-1`
   - **AWS Profile:** (optional) named profile from credentials file
   - **AWS Access Key / Secret Key:** (optional) overrides credential chain
3. Click **Save**, then set as **Active Provider**

> Available Bedrock model IDs: [docs.aws.amazon.com/bedrock/latest/userguide/model-cards.html](https://docs.aws.amazon.com/bedrock/latest/userguide/model-cards.html)
>
> **Note:** AWS Bedrock has its own service quotas (requests per minute, tokens per minute per model) and separate pricing per model. Check your quota limits and costs at:
> - Pricing: [aws.amazon.com/bedrock/pricing](https://aws.amazon.com/bedrock/pricing/)
> - Quotas: [docs.aws.amazon.com/bedrock/latest/userguide/quotas.html](https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html)
>
> It is your responsibility to monitor usage and ensure you operate within your allocated quotas.

### Setting the Active Provider

After adding a provider, select it from the **Active Provider** dropdown in the Settings tab. Only one provider is active at a time. You can switch providers at any time — the active provider is used for all Explain, Query, and Actions operations.

Click **Test** next to any provider to verify the connection is working.

## Your First Analysis

### Step 1: Navigate to a Function

In IDA's Disassembly or Pseudocode view, navigate to any function you want to analyze. The current function address is displayed at the top of IDAssist tabs.

### Step 2: Generate an Explanation

Click the **Explain** tab, then click **Explain Function**. IDAssist will:
- Extract the function's pseudocode (if Hex-Rays is available) or disassembly
- Send it to your active LLM provider
- Stream the explanation into the display area
- Automatically generate a security analysis panel

### Step 3: Review Security Analysis

Below the explanation, the Security Analysis panel shows:
- **Risk Level** — Overall risk assessment
- **Activity Profile** — What the function does (network, file I/O, crypto, etc.)
- **Security Flags** — Specific vulnerability indicators
- **Network APIs / File I/O APIs** — Detected security-relevant API calls

### Step 4: Ask Follow-up Questions

Switch to the **Query** tab and ask questions about the function. Use context macros to include code:

- `#func` — Inserts the current function's pseudocode or disassembly
- `#addr` — Inserts the address under the cursor
- `#line` — Inserts the current disassembly line
- `#range(0x401000, 0x401100)` — Inserts disassembly for an address range

Example query:
```
What vulnerabilities exist in this function? #func
```

## Next Steps

- [Explain Workflow](workflows/explain-workflow.md) — Build a documentation set for the binary
- [Query Workflow](workflows/query-workflow.md) — Advanced querying with MCP tools and ReAct agent
- [Semantic Graph Workflow](workflows/semantic-graph-workflow.md) — Build a knowledge graph of the binary
- [Actions Tab](tabs/actions-tab.md) — AI-powered rename and retype suggestions
- [RAG Tab](tabs/rag-tab.md) — Upload reference documents for context
- [Settings Tab](tabs/settings-tab.md) — Full provider and configuration reference

## Troubleshooting

### Plugin Not Loading

- Verify `idassist_plugin.py` is in `~/.idapro/plugins/` (or your platform's IDA plugins directory)
- Check the IDA Output window for error messages
- Ensure all dependencies from `requirements.txt` are installed in IDA's Python environment
- Confirm IDA Pro 9.0+ with Python 3 support

### No Response from LLM

- Go to Settings and click **Test** on your active provider
- Check the URL, API key, and model name
- For Ollama, verify the server is running: `curl http://localhost:11434/api/tags`
- Check the IDA Output window for error details

### Hex-Rays Not Available

- IDAssist works without Hex-Rays but falls back to disassembly instead of pseudocode
- Some features (variable renaming, struct creation) require Hex-Rays
- Ensure Hex-Rays is licensed and loaded for your processor type

### Connection Issues

- For self-signed TLS certificates, enable **Disable TLS** in the provider settings
- For corporate proxies, consider using a LiteLLM proxy as an intermediary
- Check that your firewall allows outbound connections to the LLM provider

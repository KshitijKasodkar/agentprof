"""Name and classify the endpoints an agent talks to, from payload heads.

TLS traffic is encrypted, but the first message a client sends, the
ClientHello, is not: it carries the server name the client wants (SNI) and the
protocols it offers (ALPN: h2, http/1.1). Plain HTTP (local model servers such
as Ollama, vLLM) shows the request line and Host header directly.
"""
import re

LLM_HOSTS = [
    r"(^|\.)api\.anthropic\.com$",
    r"(^|\.)generativelanguage\.googleapis\.com$", r"(^|\.)cloudcode-pa\.googleapis\.com$",
    r"(^|\.)aiplatform\.googleapis\.com$", r"(^|\.)api\.openai\.com$", r"^chatgpt\.com$",
    r"(^|\.)openrouter\.ai$", r"(^|\.)api\.groq\.com$", r"(^|\.)api\.deepseek\.com$",
    r"(^|\.)api\.mistral\.ai$", r"(^|\.)dashscope.*\.aliyuncs\.com$", r"(^|\.)api\.together\.xyz$",
    r"(^|\.)api\.x\.ai$", r"(^|\.)bedrock-runtime\..*\.amazonaws\.com$", r"(^|\.)api\.githubcopilot\.com$",
    r"(^|\.)inference\.ai\.azure\.com$", r"(^|\.)openai\.azure\.com$", r"(^|\.)api\.moonshot\.",
    r"(^|\.)api\.cerebras\.ai$", r"(^|\.)api\.fireworks\.ai$", r"(^|\.)portal\.qwen\.ai$",
]
LLM_PATHS = ["/v1/messages", "/chat/completions", "/v1/responses", "/api/chat", "/api/generate",
             ":generateContent", ":streamGenerateContent", "/v1/completions", "/backend-api/codex"]
CATEGORIES = [
    ("telemetry", [r"statsig", r"sentry\.io$", r"datadoghq", r"segment\.(io|com)$", r"posthog",
                   r"play\.googleapis\.com$", r"firebaselogging", r"clarity\.ms$", r"honeycomb\.io$",
                   r"otel", r"telemetry", r"mixpanel", r"amplitude", r"growthbook", r"featuregates",
                   r"browser-intake", r"logs\."]),
    ("auth", [r"oauth2\.googleapis\.com$", r"accounts\.google\.com$", r"console\.anthropic\.com$",
              r"auth\.openai\.com$", r"(^|\.)claude\.ai$", r"login\.", r"sts\.googleapis\.com$"]),
    ("package", [r"registry\.npmjs\.org$", r"(^|\.)npmjs\.(org|com)$", r"pypi\.org$", r"pythonhosted\.org$",
                 r"deb\.debian\.org$", r"archive\.ubuntu\.com$", r"security\.ubuntu\.com$",
                 r"archive\.raspberrypi\.", r"proxy\.golang\.org$", r"crates\.io$", r"static\.rust-lang\.org$",
                 r"(^|\.)yarnpkg\.com$", r"registry\.yarnpkg\.com$", r"storage\.googleapis\.com$",
                 r"downloads\.claude\.ai$"]),
    ("code-host", [r"(^|\.)github\.com$", r"githubusercontent\.com$", r"(^|\.)gitlab\.com$",
                   r"(^|\.)bitbucket\.org$"]),
    ("search/web", [r"api\.search\.brave\.com$", r"serpapi", r"duckduckgo", r"(^|\.)google\.com$",
                    r"bing\.com$", r"tavily", r"exa\.ai$"]),
]


def parse_client_hello(data: bytes):
    """-> {"sni": str|None, "alpn": [..], "tls": True} or None if not a ClientHello."""
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return None
    out = {"tls": True, "sni": None, "alpn": []}
    try:
        p = 5 + 4            # record header + handshake header
        p += 2 + 32          # client_version + random
        sid = data[p]
        p += 1 + sid
        cs = int.from_bytes(data[p:p + 2], "big")
        p += 2 + cs
        cm = data[p]
        p += 1 + cm
        ext_total = int.from_bytes(data[p:p + 2], "big")
        p += 2
        end = min(len(data), p + ext_total)
        while p + 4 <= end:
            et = int.from_bytes(data[p:p + 2], "big")
            el = int.from_bytes(data[p + 2:p + 4], "big")
            body = data[p + 4:p + 4 + el]
            if et == 0 and len(body) >= 5:        # server_name
                n = int.from_bytes(body[3:5], "big")
                out["sni"] = body[5:5 + n].decode(errors="replace")
            elif et == 16 and len(body) >= 2:     # ALPN
                q = 2
                while q < len(body):
                    ln = body[q]
                    out["alpn"].append(body[q + 1:q + 1 + ln].decode(errors="replace"))
                    q += 1 + ln
            p += 4 + el
    except (IndexError, ValueError):
        pass
    return out


HTTP_REQ = re.compile(rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (\S+) HTTP/(\d\.\d)\r\n")
HTTP_RESP = re.compile(rb"^HTTP/(\d(?:\.\d)?) (\d{3})")


def parse_http_request(data: bytes):
    m = HTTP_REQ.match(data)
    if not m:
        return None
    host = None
    hm = re.search(rb"\r\n[Hh]ost: *([^\r\n]+)", data)
    if hm:
        host = hm.group(1).decode(errors="replace")
    return {"method": m.group(1).decode(), "path": m.group(2).decode(errors="replace"),
            "http": m.group(3).decode(), "host": host}


def parse_http_response(data: bytes):
    m = HTTP_RESP.match(data)
    if not m:
        return None
    return {"status": int(m.group(2)), "http": m.group(1).decode()}


def is_llm_path(path):
    return bool(path) and any(p in path for p in LLM_PATHS)


def categorize(name, rport, raddr, paths=()):
    """category of an endpoint: llm, telemetry, auth, package, code-host, dns, local, web, other"""
    if rport == 53:
        return "dns"
    if any(is_llm_path(p) for p in paths):
        return "llm"
    host = (name or "").split(":")[0].lower()
    if host:
        for pat in LLM_HOSTS:
            if re.search(pat, host):
                return "llm"
        for cat, pats in CATEGORIES:
            for pat in pats:
                if re.search(pat, host):
                    return cat
    if raddr and (raddr.startswith("127.") or raddr == "::1"):
        if rport == 11434:
            return "llm"
        return "local"
    if rport in (443, 8443):
        return "web"
    return "other"

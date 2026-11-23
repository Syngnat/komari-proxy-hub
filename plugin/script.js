const server = require("server");
const { Buffer } = require("buffer");

const BACKEND = "http://172.17.0.1:9460";
const TIMEOUT_MS = 20000;

function isAdmin(req) {
  const principal = req.context && req.context.principal;
  const roles = principal && Array.isArray(principal.roles) ? principal.roles : [];
  return roles.indexOf("admin") >= 0;
}

function replyJson(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(body);
}

function reject(res, status, message) {
  replyJson(res, status, JSON.stringify({ error: message }));
}

function readJsonBody(req) {
  try {
    return JSON.parse(req.body || "{}");
  } catch (_) {
    return null;
  }
}

function rpcMessage(error) {
  if (error && error.message) return String(error.message);
  return "Komari RPC 调用失败";
}

async function backendFetch(path, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(BACKEND + path, {
      ...(options || {}),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function proxyRequest(req, res, upstreamPath, keys) {
  if (!isAdmin(req)) {
    reject(res, 403, "管理员权限不足");
    return;
  }
  const params = new URLSearchParams();
  for (const key of keys) {
    const value = req.query[key];
    if (typeof value === "string" && value.length > 0) {
      params.set(key, value);
    }
  }
  const suffix = params.toString();
  try {
    const response = await backendFetch(
      upstreamPath + (suffix ? "?" + suffix : ""),
      {
        headers: { Accept: "application/json" },
      },
    );
    const body = await response.text();
    if (!response.ok) {
      let message = "聚合服务返回 HTTP " + response.status;
      try {
        const parsed = JSON.parse(body);
        if (parsed && parsed.error) message = String(parsed.error);
      } catch (_) {}
      reject(res, response.status, message);
      return;
    }
    replyJson(res, 200, body);
  } catch (error) {
    const message = error && error.name === "AbortError"
      ? "聚合服务查询超时"
      : "聚合服务不可用";
    console.error("proxy-traffic proxy error:", error && error.message ? error.message : error);
    reject(res, 503, message);
  }
}

async function proxyJsonPost(req, res, upstreamPath) {
  if (!isAdmin(req)) {
    reject(res, 403, "管理员权限不足");
    return;
  }
  const body = typeof req.body === "string" ? req.body : "{}";
  if (body.length > 2 * 1024 * 1024) {
    reject(res, 413, "请求体过大");
    return;
  }
  try {
    const response = await backendFetch(upstreamPath, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json; charset=utf-8",
      },
      body,
    });
    const payload = await response.text();
    if (!response.ok) {
      let message = "聚合服务返回 HTTP " + response.status;
      try {
        const parsed = JSON.parse(payload);
        if (parsed && parsed.error) message = String(parsed.error);
      } catch (_) {}
      reject(res, response.status, message);
      return;
    }
    replyJson(res, 200, payload);
  } catch (error) {
    const message = error && error.name === "AbortError"
      ? "聚合服务请求超时"
      : "聚合服务不可用";
    console.error("proxy-traffic subscription error:", error && error.message ? error.message : error);
    reject(res, 503, message);
  }
}

async function proxySubscription(req, res) {
  const base = "http://komari.local";
  let parsed;
  try {
    parsed = new URL(req.url, base);
  } catch (_) {
    replyJson(res, 404, JSON.stringify({ error: "订阅不存在" }));
    return;
  }
  const prefix = "/proxy-traffic-sub";
  if (!parsed.pathname.startsWith(prefix)) {
    replyJson(res, 404, JSON.stringify({ error: "订阅不存在" }));
    return;
  }
  const rest = parsed.pathname.slice(prefix.length);
  let upstream = "";
  if (rest.startsWith("/s/")) {
    const code = decodeURIComponent(rest.slice(3));
    if (!/^[A-Za-z0-9_-]{4,32}$/.test(code)) {
      replyJson(res, 404, JSON.stringify({ error: "订阅不存在" }));
      return;
    }
    upstream = "/s/" + encodeURIComponent(code);
  } else {
    const parts = rest.replace(/^\/+/, "").split("/");
    const token = decodeURIComponent(parts[0] || "");
    const format = parts[1] ? decodeURIComponent(parts[1]) : "";
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(token) || (format && !/^[A-Za-z0-9_-]{1,16}$/.test(format))) {
      replyJson(res, 404, JSON.stringify({ error: "订阅不存在" }));
      return;
    }
    upstream = "/sub/" + encodeURIComponent(token) + (format ? "/" + encodeURIComponent(format) : "");
  }
  const params = new URLSearchParams();
  for (const key of ["format", "target"]) {
    const value = parsed.searchParams.get(key);
    if (value) params.set(key, value);
  }
  const suffix = params.toString();
  try {
    const ua = req.headers && req.headers["user-agent"] ? String(req.headers["user-agent"]) : "";
    const response = await backendFetch(
      upstream + (suffix ? "?" + suffix : ""),
      {
        headers: { Accept: "*/*", "User-Agent": ua },
        redirect: "manual",
      },
    );
    const text = await response.text();
    res.statusCode = response.status;
    for (const name of [
      "content-type", "content-disposition", "location",
      "cache-control", "x-robots-tag", "profile-update-interval",
    ]) {
      const value = response.headers.get(name);
      if (value) res.setHeader(name, value);
    }
    res.end(text);
  } catch (error) {
    console.error("proxy-traffic subscription forward error:", error && error.message ? error.message : error);
    replyJson(res, 503, JSON.stringify({ error: "订阅服务不可用" }));
  }
}

function buildRuleSaveCommand(path, contentB64) {
  const pyPath = JSON.stringify(path);
  return `# komari-proxy-traffic-rule-save
set -e
python3 - <<'PY'
import base64
import datetime
import json
import os
import pathlib
import secrets
import shutil
import sys

def fail(message):
    print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    sys.exit(1)

path = pathlib.Path(${pyPath})
try:
    content = base64.b64decode("${contentB64}", validate=True).decode("utf-8")
except Exception as exc:
    fail("规则内容不是有效的 base64 UTF-8：" + str(exc))
if not content.strip():
    fail("规则内容为空")
if not path.is_file():
    fail("规则文件不存在：" + str(path))
try:
    stat = path.stat()
    backup = path.with_name(
        path.name + ".bak-" + datetime.datetime.now().strftime("%Y%m%dT%H%M%S") +
        "-" + secrets.token_hex(3)
    )
    shutil.copy2(path, backup)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, stat.st_mode & 0o777)
    try:
        shutil.chown(temporary, uid=stat.st_uid, gid=stat.st_gid)
    except Exception:
        pass
    os.replace(temporary, path)
except Exception as exc:
    try:
        temporary.unlink()
    except Exception:
        pass
    fail("写入规则文件失败：" + str(exc))
print(json.dumps({
    "ok": True,
    "path": str(path),
    "backup": str(backup),
    "bytes": len(content.encode("utf-8")),
}, ensure_ascii=False))
PY`;
}

async function saveRule(req, res) {
  if (!isAdmin(req)) {
    reject(res, 403, "管理员权限不足");
    return;
  }
  const body = readJsonBody(req);
  const fileId = body && typeof body.file_id === "string" ? body.file_id.trim() : "";
  const client = body && typeof body.client === "string" ? body.client.trim() : "";
  const content = body && typeof body.content === "string" ? body.content : "";
  const contentB64 = body && typeof body.content_b64 === "string" ? body.content_b64.trim() : "";
  if (!/^[A-Fa-f0-9]{16}$/.test(fileId)) {
    reject(res, 400, "无效的规则文件 ID");
    return;
  }
  if (!/^[A-Za-z0-9-]{8,64}$/.test(client)) {
    reject(res, 400, "无效的执行节点");
    return;
  }
  if (!content || !contentB64 || content.length > 3 * 1024 * 1024) {
    reject(res, 400, "规则内容为空或过大");
    return;
  }
  if (!/^[A-Za-z0-9+/=\r\n]+$/.test(contentB64) || contentB64.length > 4 * 1024 * 1024) {
    reject(res, 400, "规则内容编码无效");
    return;
  }
  const expectedB64 = Buffer.from(content, "utf8").toString("base64");
  if (expectedB64 !== contentB64.replace(/\s+/g, "")) {
    reject(res, 400, "规则内容与编码不一致");
    return;
  }
  try {
    const stateResponse = await backendFetch("/api/proxy-traffic/rules", {
      headers: { Accept: "application/json" },
    });
    const stateText = await stateResponse.text();
    if (!stateResponse.ok) {
      reject(res, 502, "无法读取规则文件列表");
      return;
    }
    const state = JSON.parse(stateText);
    const file = (Array.isArray(state.files) ? state.files : [])
      .find((item) => item.id === fileId);
    const root = String(state.root || "").replace(/\/+$/, "");
    if (
      !file ||
      !file.path ||
      !root ||
      !file.path.startsWith(root + "/") ||
      !file.path.endsWith("/mihomo.yaml")
    ) {
      reject(res, 400, "规则文件不在允许的目录内");
      return;
    }
    const target = state.target && typeof state.target === "object" ? state.target : {};
    const targetIp = String(target.ip || "").trim();
    const targetName = String(target.name || "").trim();
    if (targetIp || targetName) {
      const clients = await server.call("admin:listClients");
      const selected = (Array.isArray(clients) ? clients : [])
        .find((item) => String(item.uuid || "") === client);
      const allowed = selected && (
        (targetIp && String(selected.ipv4 || "") === targetIp) ||
        (targetName && String(selected.name || "").includes(targetName))
      );
      if (!allowed) {
        reject(res, 400, "规则文件只存在于指定节点，不能保存到其他 VPS");
        return;
      }
    }
    const preparedResponse = await backendFetch("/api/proxy-traffic/rules/prepare", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({ file_id: fileId, content }),
    });
    const preparedText = await preparedResponse.text();
    if (!preparedResponse.ok) {
      let message = "规则校验失败";
      try {
        const parsed = JSON.parse(preparedText);
        if (parsed && parsed.error) message = String(parsed.error);
      } catch (_) {}
      reject(res, preparedResponse.status, message);
      return;
    }
    const prepared = JSON.parse(preparedText);
    if (prepared.path !== file.path) {
      reject(res, 400, "规则文件路径发生变化，请刷新后重试");
      return;
    }
    const command = buildRuleSaveCommand(prepared.path, contentB64);
    if (command.length > 200000) {
      reject(res, 413, "规则文件过大，无法通过 Komari 远程执行保存");
      return;
    }
    const task = await server.call("admin:exec", {
      clients: [client],
      command,
    });
    replyJson(res, 200, JSON.stringify({
      task_id: task && task.task_id ? task.task_id : "",
      file_id: fileId,
      path: prepared.path,
    }));
  } catch (error) {
    reject(res, 502, error && error.message ? String(error.message) : "保存规则失败");
  }
}

function load() {
  server.route("GET", "/api/proxy-traffic/summary", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/summary", ["hours"]);
  });
  server.route("GET", "/api/proxy-traffic/timeline", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/timeline", ["hours", "node_id", "ip", "ips"]);
  });
  server.route("GET", "/api/proxy-traffic/device-map", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/device-map", [
      "node_id", "label", "ips", "device_id", "action",
    ]);
  });
  server.route("GET", "/api/proxy-traffic/ip-sites", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/ip-sites", [
      "hours", "node_id", "ip",
    ]);
  });
  server.route("GET", "/api/proxy-traffic/health", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/health", []);
  });
  server.route("GET", "/api/proxy-traffic/sub/state", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/sub/state", []);
  });
  server.route("GET", "/api/proxy-traffic/rules", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/rules", []);
  });
  server.route("GET", "/api/proxy-traffic/rules/file", (req, res) => {
    return proxyRequest(req, res, "/api/proxy-traffic/rules/file", ["file_id"]);
  });
  server.route("POST", "/api/proxy-traffic/rules/parse", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/rules/parse");
  });
  server.route("POST", "/api/proxy-traffic/rules/prepare", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/rules/prepare");
  });
  server.route("POST", "/api/proxy-traffic/rules/save", (req, res) => {
    return saveRule(req, res);
  });
  server.route("POST", "/api/proxy-traffic/sub/nodes", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/sub/nodes");
  });
  server.route("POST", "/api/proxy-traffic/sub/nodes/delete", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/sub/nodes/delete");
  });
  server.route("POST", "/api/proxy-traffic/sub/nodes/import", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/sub/nodes/import");
  });
  server.route("POST", "/api/proxy-traffic/sub/nodes/import-rules", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/sub/nodes/import-rules");
  });
  server.route("POST", "/api/proxy-traffic/sub/subscriptions", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/sub/subscriptions");
  });
  server.route("POST", "/api/proxy-traffic/sub/subscriptions/delete", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/sub/subscriptions/delete");
  });
  server.route("POST", "/api/proxy-traffic/sub/subscriptions/rotate", (req, res) => {
    return proxyJsonPost(req, res, "/api/proxy-traffic/sub/subscriptions/rotate");
  });
  server.route("GET", "/proxy-traffic-sub/*rest", (req, res) => {
    return proxySubscription(req, res);
  });

  server.route("GET", "/api/proxy-traffic/provision/clients", async (req, res) => {
    if (!isAdmin(req)) {
      reject(res, 403, "管理员权限不足");
      return;
    }
    try {
      const clients = await server.call("admin:listClients");
      const list = (Array.isArray(clients) ? clients : []).map((client) => ({
        uuid: String(client.uuid || ""),
        name: String(client.name || client.uuid || ""),
        ipv4: String(client.ipv4 || ""),
        ipv6: String(client.ipv6 || ""),
        os: String(client.os || ""),
        arch: String(client.arch || ""),
        region: String(client.region || ""),
      })).filter((client) => client.uuid);
      replyJson(res, 200, JSON.stringify({ clients: list }));
    } catch (error) {
      reject(res, 502, rpcMessage(error));
    }
  });

  server.route("POST", "/api/proxy-traffic/provision/apply", async (req, res) => {
    if (!isAdmin(req)) {
      reject(res, 403, "管理员权限不足");
      return;
    }
    const body = readJsonBody(req);
    const client = body && typeof body.client === "string" ? body.client.trim() : "";
    const command = body && typeof body.command === "string" ? body.command.trim() : "";
    if (!/^[A-Za-z0-9-]{8,64}$/.test(client)) {
      reject(res, 400, "无效的节点 UUID");
      return;
    }
    if (!command || command.length > 200000 || !command.startsWith("# komari-proxy-traffic-provision")) {
      reject(res, 400, "无效的部署脚本");
      return;
    }
    try {
      const task = await server.call("admin:exec", {
        clients: [client],
        command,
      });
      replyJson(res, 200, JSON.stringify({ task_id: task && task.task_id ? task.task_id : "" }));
    } catch (error) {
      reject(res, 502, rpcMessage(error));
    }
  });

  server.route("GET", "/api/proxy-traffic/provision/task", async (req, res) => {
    if (!isAdmin(req)) {
      reject(res, 403, "管理员权限不足");
      return;
    }
    const taskId = typeof req.query.task_id === "string" ? req.query.task_id.trim() : "";
    if (!/^[A-Za-z0-9-]{8,64}$/.test(taskId)) {
      reject(res, 400, "无效的任务 ID");
      return;
    }
    try {
      const task = await server.call("admin:getTaskById", { task_id: taskId });
      replyJson(res, 200, JSON.stringify(task || {}));
    } catch (error) {
      reject(res, 502, rpcMessage(error));
    }
  });
  console.log("proxy-traffic plugin loaded");
}

function unload() {
  console.log("proxy-traffic plugin unloaded");
}

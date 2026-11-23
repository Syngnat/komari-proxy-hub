const server = require("server");

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
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(
      BACKEND + upstreamPath + (suffix ? "?" + suffix : ""),
      {
        headers: { Accept: "application/json" },
        signal: controller.signal,
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
  } finally {
    clearTimeout(timer);
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

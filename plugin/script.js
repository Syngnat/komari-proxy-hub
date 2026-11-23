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
  console.log("proxy-traffic plugin loaded");
}

function unload() {
  console.log("proxy-traffic plugin unloaded");
}

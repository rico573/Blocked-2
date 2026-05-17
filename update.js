import fs from "fs";

const CF_API_TOKEN = process.env.CF_API_TOKEN;
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;

const PHASE = "http_request_firewall_custom";
const RULE_DESCRIPTION = "AUTO_BLOCK_SPAM_REFERRER_AND_BAD_BOTS";
const RULE_ACTION = "managed_challenge";
// Test ổn rồi đổi thành: "block"

if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
  throw new Error("Missing CF_API_TOKEN or CF_ACCOUNT_ID");
}

const config = JSON.parse(fs.readFileSync("spam.json", "utf8"));

function escapeCloudflareString(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function cleanList(list) {
  return (list || [])
    .map(function (item) {
      return String(item).trim();
    })
    .filter(Boolean);
}

function buildExpression() {
  const parts = [];

  for (const keyword of cleanList(config.keywords)) {
    const k = escapeCloudflareString(keyword.toLowerCase());
    parts.push('(lower(http.referer) contains "' + k + '")');
  }

  for (const domain of cleanList(config.blocked_domains)) {
    const d = escapeCloudflareString(domain.toLowerCase());
    parts.push('(lower(http.referer) contains "' + d + '")');
  }

  for (const ip of cleanList(config.blocked_ips)) {
    parts.push("(ip.src eq " + ip + ")");
  }

  for (const tld of cleanList(config.blocked_tlds)) {
    const cleanTld = tld.toLowerCase().replace(/^\./, "");
    const t = escapeCloudflareString(cleanTld);
    parts.push('(lower(http.referer) contains ".' + t + '")');
  }

  const botWhitelist = cleanList(config.bot_whitelist).map(function (bot) {
    return bot.toLowerCase();
  });

  if (botWhitelist.length) {
    const botAllowConditions = botWhitelist.map(function (bot) {
      const b = escapeCloudflareString(bot);
      return 'not lower(http.user_agent) contains "' + b + '"';
    });

    parts.push(
      "(" +
        '\n      lower(http.user_agent) contains "bot"' +
        "\n      and not cf.client.bot" +
        "\n      and " +
        botAllowConditions.join("\n      and ") +
        "\n    )"
    );
  }

  parts.push(
    "(" +
      '\n    http.request.uri.path contains "/redirect"' +
      '\n    and http.request.uri.query contains "url="' +
      '\n    and not http.request.uri.path contains "/mlink/"' +
      "\n  )"
  );

  parts.push(
    "(" +
      '\n    ip.geoip.country in {"US" "SG"}' +
      "\n    and not (" +
      "\n      cf.client.bot" +
      '\n      and lower(http.user_agent) contains "googlebot"' +
      "\n    )" +
      "\n  )"
  );

  if (!parts.length) {
    throw new Error("No rules generated from spam.json");
  }

  const spamExpression = parts.join("\n      or\n      ");
  const whitelistIps = cleanList(config.whitelist_ips);

  let whitelistIpCondition = "";
  if (whitelistIps.length) {
    whitelistIpCondition =
      "\n    not ip.src in {" + whitelistIps.join(" ") + "}" + "\n    and";
  }

  return (
    "(" +
    whitelistIpCondition +
    '\n    not http.request.uri.path contains "/wp-admin"' +
    '\n    and not http.request.uri.path contains "/wp-login.php"' +
    '\n    and not http.request.uri.path contains "/wp-json"' +
    '\n    and not http.request.uri.path contains "/xmlrpc.php"' +
    '\n    and not http.request.uri.path contains "/wp-cron.php"' +
    '\n    and not http.request.uri.path contains "/admin-ajax.php"' +
    "\n    and (" +
    "\n      " +
    spamExpression +
    "\n    )" +
    "\n  )"
  );
}

async function apiFetch(url, options) {
  options = options || {};

  const headers = Object.assign(
    {
      Authorization: "Bearer " + CF_API_TOKEN,
      "Content-Type": "application/json"
    },
    options.headers || {}
  );

  const res = await fetch(url, Object.assign({}, options, { headers: headers }));
  const text = await res.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new Error("Invalid JSON response: " + text);
  }

  if (!data.success) {
    throw new Error(JSON.stringify(data.errors || data));
  }

  return data;
}

async function listAllZones() {
  let page = 1;
  const perPage = 50;
  const zones = [];

  while (true) {
    const url =
      "https://api.cloudflare.com/client/v4/zones" +
      "?account.id=" +
      encodeURIComponent(CF_ACCOUNT_ID) +
      "&status=active" +
      "&page=" +
      page +
      "&per_page=" +
      perPage;

    const data = await apiFetch(url);

    zones.push.apply(zones, data.result);

    const totalPages = (data.result_info && data.result_info.total_pages) || 1;
    if (page >= totalPages) break;

    page++;
  }

  return zones;
}

async function getEntrypointRuleset(zoneId) {
  const url =
    "https://api.cloudflare.com/client/v4/zones/" +
    zoneId +
    "/rulesets/phases/" +
    PHASE +
    "/entrypoint";

  const res = await fetch(url, {
    headers: {
      Authorization: "Bearer " + CF_API_TOKEN,
      "Content-Type": "application/json"
    }
  });

  const data = await res.json();

  if (data.success) return data.result;

  const errorText = JSON.stringify(data.errors || "").toLowerCase();

  if (
    errorText.indexOf("not found") !== -1 ||
    errorText.indexOf("could not find entrypoint ruleset") !== -1
  ) {
    return null;
  }

  throw new Error(JSON.stringify(data.errors || data));
}

async function createEntrypointRuleset(zoneId) {
  const url =
    "https://api.cloudflare.com/client/v4/zones/" + zoneId + "/rulesets";

  const data = await apiFetch(url, {
    method: "POST",
    body: JSON.stringify({
      name: "default",
      kind: "zone",
      phase: PHASE,
      rules: []
    })
  });

  return data.result;
}

async function updateEntrypointRuleset(zoneId, rulesetId, rulesetPayload) {
  const url =
    "https://api.cloudflare.com/client/v4/zones/" +
    zoneId +
    "/rulesets/" +
    rulesetId;

  await apiFetch(url, {
    method: "PUT",
    body: JSON.stringify(rulesetPayload)
  });
}

async function upsertRuleForZone(zone, expression) {
  let ruleset = await getEntrypointRuleset(zone.id);

  if (!ruleset) {
    console.log("Creating ruleset for: " + zone.name);
    ruleset = await createEntrypointRuleset(zone.id);
  }

  const rules = ruleset.rules || [];

  const ruleIndex = rules.findIndex(function (rule) {
    return rule.description === RULE_DESCRIPTION;
  });

  const newRule = {
    action: RULE_ACTION,
    expression: expression,
    description: RULE_DESCRIPTION,
    enabled: true
  };

  if (ruleIndex >= 0) {
    rules[ruleIndex] = Object.assign({}, rules[ruleIndex], newRule);
  } else {
    rules.push(newRule);
  }

  await updateEntrypointRuleset(zone.id, ruleset.id, {
    name: ruleset.name || "default",
    kind: ruleset.kind || "zone",
    phase: PHASE,
    rules: rules
  });

  console.log("OK: " + zone.name);
}

async function main() {
  const expression = buildExpression();

  console.log("Cloudflare expression:");
  console.log(expression);

  const zones = await listAllZones();

  console.log("Found " + zones.length + " active zones");

  let ok = 0;
  let fail = 0;

  for (const zone of zones) {
    try {
      await upsertRuleForZone(zone, expression);
      ok++;
    } catch (error) {
      fail++;
      console.error("FAIL: " + zone.name + " - " + error.message);
    }
  }

  console.log("Done. OK: " + ok + ", FAIL: " + fail);
}

main().catch(function (error) {
  console.error(error);
  process.exit(1);
});

// Browser test: loads the BUILT single-file HTML in headless Chromium and checks the
// promises the README makes, in the environment users actually run.
//   node test/browser.test.js            (needs: npm i --no-save playwright@<pinned>;
//                                          npx playwright install chromium)
// Set PW_CHROMIUM=/path/to/chrome to use an existing Chromium instead of Playwright's.
//
// Checks: zero CSP violations and zero page errors (the hash CSP must cover the page's
// own scripts), no request ever leaves file://, all three modes render the fixtures,
// a hostile export executes nothing, injected markup is inert even if escaping fails,
// the public build has no tenant/partner analyzers, and the downloaded report is inert.
const fs = require("fs"); const path = require("path");
const { chromium } = require("playwright");
const ROOT = path.join(__dirname, "..");
const LOCAL = "file://" + path.join(ROOT, "blast-radius-local.html");
const PUBLIC = "file://" + path.join(ROOT, "blast-radius-public.html");
const fixture = n => JSON.parse(fs.readFileSync(path.join(ROOT, "fixtures", n), "utf8"));

let ok = 0, fail = 0; const A = (c, m) => { (c ? ok++ : fail++); console.log((c ? "PASS " : "FAIL ") + m); };

async function open(browser, url) {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  const log = { errors: [], csp: [], requests: [] };
  page.on("pageerror", e => log.errors.push(e.message));
  page.on("console", m => {
    if (m.type() !== "error") return;
    (/Content Security Policy|Refused to/i.test(m.text()) ? log.csp : log.errors).push(m.text().slice(0, 200));
  });
  // Anything that isn't the file itself, a data: URI or a blob: is a network attempt.
  await ctx.route("**/*", route => {
    const u = route.request().url();
    if (/^(file|data|blob|about):/.test(u)) return route.continue();
    log.requests.push(u); return route.abort();
  });
  await page.goto(url);
  return { ctx, page, log };
}

const HOSTILE = '<img src=x onerror="window.__hit=(window.__hit||[]).concat(1)">';
function hostileTenant() {
  const d = fixture("tenant-fixture-v091.json");
  d.tenantId += HOSTILE;
  d.servicePrincipals.forEach(sp => { sp.displayName += HOSTILE; sp.appId += HOSTILE; });
  (d.groups || []).forEach(g => { g.displayName += HOSTILE; });
  return d;
}

(async () => {
  const browser = await chromium.launch(process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {});
  try {
    // ---------- offline build ----------
    {
      const { ctx, page, log } = await open(browser, LOCAL);
      A(await page.locator("#mode-tenant").count() === 1 && await page.locator("#mode-partner").count() === 1,
        "local: all three modes present");

      // single-app
      await page.locator("#presets button").first().click();
      await page.click("#analyze");
      A((await page.locator("#results").innerText()).length > 200, "local: single-app preset analyzes");

      // tenant, hostile export
      await page.click("#mode-tenant");
      await page.fill("#tenant-paste", JSON.stringify(hostileTenant()));
      await page.click("#tanalyze");
      await page.waitForSelector(".app-row");
      A(await page.locator(".app-row").count() === 6, "local: hostile tenant export renders all 6 apps");
      A(await page.evaluate(() => (window.__hit || []).length) === 0, "local: hostile names and ids execute nothing");

      // downloaded report
      const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#tenant-results #xb-dl")]);
      const reportPath = await dl.path();
      const report = fs.readFileSync(reportPath, "utf8");
      A(/script-src 'none'/.test(report) && !/<script/i.test(report), "report: CSP forbids script and none is present");
      const r = await open(browser, "file://" + reportPath);
      await r.page.waitForTimeout(300);
      A(await r.page.evaluate(() => (window.__hit || []).length) === 0 && r.log.errors.length === 0,
        "report: opens cleanly and the hostile names in it execute nothing");
      A(r.log.requests.length === 0, `report: no network requests (${r.log.requests.join(", ") || "none"})`);
      await r.ctx.close();

      // partner
      await page.click("#mode-partner");
      await page.fill("#partner-paste", JSON.stringify(fixture("partner-fixture.json")));
      await page.click("#panalyze");
      await page.waitForSelector(".cust-row");
      A(await page.locator(".cust-row").count() === 3, "local: partner export maps 3 customers");

      // defence in depth: even raw markup written by page code must not run
      await page.evaluate(() => {
        document.getElementById("tenant-results").innerHTML = '<img src=x onerror="window.__inj=1"><svg onload="window.__inj=1"></svg>';
      });
      await page.waitForTimeout(300);
      A(await page.evaluate(() => !window.__inj), "local: hash CSP blocks injected inline handlers");

      // The injected <img>s above are expected to trip img-src/script-src; anything
      // else on the CSP list means the page's own code was blocked.
      const ownCsp = log.csp.filter(t => !/img-src|inline event handler|script-src-attr|'unsafe-hashes'/i.test(t));
      A(ownCsp.length === 0, `local: the page's own scripts run under its CSP${ownCsp.length ? "\n       " + ownCsp[0] : ""}`);
      A(log.errors.length === 0, `local: no page errors${log.errors.length ? "\n       " + log.errors.slice(0, 3).join("\n       ") : ""}`);
      A(log.requests.length === 0, `local: no network requests${log.requests.length ? " (" + log.requests.join(", ") + ")" : ""}`);
      await ctx.close();
    }

    // ---------- public build ----------
    {
      const { ctx, page, log } = await open(browser, PUBLIC);
      A(await page.locator("#tenant-mode, #partner-mode, #tenant-paste, #partner-paste").count() === 0,
        "public: no tenant or partner analyzer in the page");
      A(await page.evaluate(() => typeof analyzeTenant === "undefined" && typeof analyzePartner === "undefined"),
        "public: tenant and partner engines are not in the script");
      await page.locator("#presets button").first().click();
      await page.click("#analyze");
      A((await page.locator("#results").innerText()).length > 200, "public: single-app preset analyzes");
      A(log.csp.length === 0 && log.errors.length === 0, `public: no CSP violations or page errors${[...log.csp, ...log.errors].slice(0, 2).map(x => "\n       " + x).join("")}`);
      A(log.requests.length === 0, "public: no network requests");
      await ctx.close();
    }
  } finally {
    await browser.close();
  }
  console.log(`\n${ok} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });

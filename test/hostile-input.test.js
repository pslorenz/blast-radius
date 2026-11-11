// Hostile-input regression: attacker-controlled strings must never reach the page or the
// exported report as markup, and must never change a verdict. Run: node test/hostile-input.test.js
//
// Why: display names in an export are chosen by whoever created the object. A vendor app's
// name is written by the vendor, i.e. by the attacker in the scenario this tool exists for.
// Identifiers (appId, tenant ids) come from Graph, but the export is a file someone hands
// you, so they are treated as untrusted too.
//
// How: the real engine and renderers run in a vm sandbox (same stubs as fixture.test.js),
// every innerHTML write is captured, and the exported report is built. Each injected value
// carries a unique token, so every finding names the fixture, field and payload. For each
// payload P the output must contain escapeHtml(P), never P itself (unescaped) and never
// escapeHtml(escapeHtml(P)) (double-escaped, which shows readers "&amp;lt;" and means two
// layers disagree about who escapes). Across the passes every payload visits every field.
//
// Tenant permission, role and scope strings are resolved through the knowledge base and
// unknown ones are dropped, so they are injected as unknown entries and must not appear at
// all. Unknown GDAP roles are shown on purpose, so those are checked for escaping instead.
const vm = require("vm"); const fs = require("fs"); const path = require("path");
const ROOT = path.join(__dirname, "..");

// ---------- sandbox (fixture.test.js stubs + innerHTML capture) ----------
const SINK = [];
function makeEl(id){return{id:id||"el",_html:"",dataset:{},style:{},classList:{_s:new Set(),add(c){this._s.add(c)},remove(c){this._s.delete(c)},toggle(c){this._s.has(c)?this._s.delete(c):this._s.add(c)},contains(c){return this._s.has(c)}},hidden:false,tabIndex:0,value:"",textContent:"",files:[],children:[],setAttribute(){},getAttribute(){return null},hasAttribute(){return false},addEventListener(){},appendChild(c){this.children.push(c);return c;},querySelector(){return makeEl()},querySelectorAll(){return[]},closest(){return makeEl()},scrollIntoView(){},focus(){},click(){},remove(){},get innerHTML(){return this._html},set innerHTML(v){this._html=v;SINK.push(String(v));}};}
const els={};
const sb={document:{getElementById:id=>els[id]||(els[id]=makeEl(id)),querySelector:()=>null,querySelectorAll:()=>[],addEventListener:()=>{},createElement:t=>makeEl(t),body:{dataset:{},appendChild(c){return c;},removeChild(){}}},navigator:{clipboard:{writeText:()=>Promise.resolve()}},FileReader:class{readAsText(){this.onload&&this.onload();}},alert:()=>{},setTimeout:fn=>fn(),console,Blob:class{constructor(a){this.parts=a}},URL:{createObjectURL:()=>"blob:x",revokeObjectURL(){}}};
vm.createContext(sb);
vm.runInContext(fs.readFileSync(path.join(ROOT,"kb.js"),"utf8")+"\n"+fs.readFileSync(path.join(ROOT,"app.js"),"utf8"), sb);
const run = (code, vars) => { Object.assign(sb, vars || {}); return vm.runInContext(code, sb); };
const esc = run("escapeHtml");

let ok = 0, fail = 0; const A = (c, m) => { (c ? ok++ : fail++); console.log((c ? "PASS " : "FAIL ") + m); };

// ---------- payloads ----------
const PAYLOADS = [
  ["tag",          t => `<b data-br="${t}">${t}</b>`],
  ["img-onerror",  t => `<img src=x onerror="__hit('${t}')">`],
  ["attr-dq",      t => `"><svg onload="__hit('${t}')">`],
  ["attr-sq",      t => `'><svg onload='__hit("${t}")'>`],
  ["attr-inject",  t => `" autofocus onfocus="__hit('${t}')" x="`],
  ["close-tags",   t => `</title></style></textarea><b data-br="${t}">`],
  ["entities",     t => `&lt;b data-br=&quot;${t}&quot;&gt; &amp; ${t}`],
];
const NASTY = ["__proto__", "constructor", "hasOwnProperty", "", " ", "\u202Eexe.gnp", "a".repeat(20000),
  "\u0000\u001b[31m", "😀👩‍👩‍👧", "%s%n", "${7*7}{{7*7}}"];
const MS_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
const NAME_KEYS = new Set(["displayName", "DisplayName", "name", "appDisplayName"]);
const ID_KEYS = new Set(["id", "appId", "tenantId", "partnerTenantId", "appOwnerOrganizationId", "relationshipId", "accessContainerId"]);
const KB_LISTS = new Set(["appRoles", "directoryRoles", "eligibleRoles"]);

let seq = 0;
const walk = (node, fn, key = "", p = "$") => {
  if (Array.isArray(node)) node.forEach((v, i) => typeof v === "string" ? fn(v, key, x => { node[i] = x; }, `${p}[${i}]`, node) : walk(v, fn, key, `${p}[${i}]`));
  else if (node && typeof node === "object") for (const k of Object.keys(node)) {
    const v = node[k];
    if (typeof v === "string") fn(v, k, x => { node[k] = x; }, `${p}.${k}`, node); else walk(v, fn, k, `${p}.${k}`);
  }
};

// Mutate a fresh copy. Names get a payload appended per field; each identifier value is
// remapped consistently everywhere it appears so ownership/membership links survive.
function mutate(raw, offset, label) {
  const data = JSON.parse(raw), issued = [];
  const pick = n => PAYLOADS[(n + offset) % PAYLOADS.length];
  const ids = new Map();
  walk(data, (v, k) => { if (ID_KEYS.has(k) && v.toLowerCase() !== MS_TENANT && !ids.has(v)) ids.set(v, null); });
  let n = 0;
  for (const v of ids.keys()) {
    const [pid, mk] = pick(n++), t = `BRT${++seq}X`, P = mk(t);
    ids.set(v, v + " " + P); issued.push({ t, P, pid, field: `identifier "${v}"`, label });
  }
  walk(data, (v, k, set, p) => {
    if (ids.has(v) && ids.get(v)) { set(ids.get(v)); return; }
    if (NAME_KEYS.has(k)) { const [pid, mk] = pick(n++), t = `BRT${++seq}X`, P = mk(t); set(v + " " + P); issued.push({ t, P, pid, field: p, label }); }
  });
  // unknown permission/role/scope entries: the KB must drop them before rendering
  const unknown = [];
  (function addUnknown(node) {
    if (Array.isArray(node)) return node.forEach(addUnknown);
    if (!node || typeof node !== "object") return;
    for (const k of Object.keys(node)) {
      if (KB_LISTS.has(k) && Array.isArray(node[k])) { const [, mk] = pick(n++), t = `BRT${++seq}X`; node[k].push(mk(t)); unknown.push({ t, field: `unknown entry in ${k}`, label }); }
      else if (k === "scope" && typeof node[k] === "string") { const t = `BRT${++seq}X`; node[k] += ` Evil.${t}<b>`; unknown.push({ t, field: "unknown delegated scope", label }); }
      // GDAP roles not in the KB are shown by design (so a new role is visible), so they must be escaped
      else if (k === "roleDefinitionId" && typeof node[k] === "string") { const [pid, mk] = pick(n++), t = `BRT${++seq}X`, P = mk(t); node[k] = P; issued.push({ t, P, pid, field: "unknown GDAP roleDefinitionId", label }); }
      else addUnknown(node[k]);
    }
  })(data);
  return { data, issued, unknown };
}

const NOW = Date.parse("2026-10-22T12:00:00Z");
function renderAll(kind, data) {
  SINK.length = 0;
  let res;
  if (kind === "tenant") { res = run("analyzeTenant(__d, {since:'2026-10-01', now:__now})", { __d: data, __now: NOW }); run("renderTenant(__r)", { __r: res }); }
  else { res = run("analyzePartner(__d, {now:__now})", { __d: data, __now: NOW }); run("renderPartner(__r)", { __r: res }); }
  const report = run(`buildReportHTML('${kind}')`);
  return { res, out: SINK.join("\n") + "\n" + report, report };
}

const verdicts = (kind, res) => kind === "tenant"
  ? JSON.stringify(res.sps.map(s => [s.id && String(s.id).split(" ")[0], s.finalSev, !!s.viaPim, (s.credFlags || []).map(f => f.code).sort()]).sort())
  : JSON.stringify(res.custList.map(c => [String(c.id).split(" ")[0], c.sev, c.relstat]).sort());

const FIXTURES = fs.readdirSync(path.join(ROOT, "fixtures")).filter(f => f.endsWith(".json"))
  .map(f => ({ f, kind: /partner|gdap/i.test(f) ? "partner" : "tenant", raw: fs.readFileSync(path.join(ROOT, "fixtures", f), "utf8") }));

// ---------- 1. escaping: every attacker string escaped exactly once, everywhere ----------
for (const { f, kind, raw } of FIXTURES) {
  const unescaped = [], doubled = [], mangled = [], leaked = [], seen = new Set(), all = new Set();
  let crash = null;
  for (let off = 0; off < PAYLOADS.length; off++) {
    const { data, issued, unknown } = mutate(raw, off, `${f} pass ${off + 1}`);
    let out;
    try { ({ out } = renderAll(kind, data)); } catch (e) { crash = `${f} pass ${off + 1}: ${e.message}`; break; }
    for (const it of issued) {
      all.add(it.field);
      if (out.includes(it.P)) unescaped.push(it);
      else if (out.includes(esc(esc(it.P)))) doubled.push(it);
      else if (out.includes(esc(it.P))) seen.add(it.field);
      else if (out.includes(it.t)) mangled.push(it);
    }
    for (const u of unknown) if (out.includes(u.t)) leaked.push(u);
  }
  const show = list => list.slice(0, 6).map(x => `\n       ${x.field} [${x.pid || ""}] (${x.label})`).join("") + (list.length > 6 ? `\n       ... ${list.length - 6} more` : "");
  A(!crash, `${f}: renders without throwing on hostile names and ids${crash ? "\n       " + crash : ""}`);
  A(unescaped.length === 0, `${f}: no attacker string reaches HTML unescaped${show(unescaped)}`);
  A(doubled.length === 0, `${f}: no attacker string is escaped twice${show(doubled)}`);
  A(mangled.length === 0, `${f}: no attacker string is rendered partly escaped${show(mangled)}`);
  A(leaked.length === 0, `${f}: unknown permissions/roles/scopes never rendered${show(leaked)}`);
  A(seen.size > 0, `${f}: coverage, ${seen.size}/${all.size} injected fields rendered (escaped) somewhere`);
}

// ---------- 2. names never change a verdict (names are not trust signals) ----------
for (const { f, kind, raw } of FIXTURES) {
  const base = verdicts(kind, renderAll(kind, JSON.parse(raw)).res);
  const same = JSON.parse(raw); walk(same, (v, k, set) => { if (NAME_KEYS.has(k)) set("Microsoft Graph"); });
  const nasty = JSON.parse(raw); let i = 0; walk(nasty, (v, k, set) => { if (NAME_KEYS.has(k)) set(NASTY[i++ % NASTY.length]); });
  let rSame, rNasty, err = null;
  try { rSame = renderAll(kind, same); rNasty = renderAll(kind, nasty); } catch (e) { err = e.message; }
  A(!err && verdicts(kind, rSame.res) === base, `${f}: every name set to "Microsoft Graph" leaves all verdicts and flags unchanged${err ? " (" + err + ")" : ""}`);
  A(!err && verdicts(kind, rNasty.res) === base, `${f}: prototype-key, empty, bidi and huge names leave all verdicts and flags unchanged`);
  if (kind === "tenant" && !err) {
    const rows = (rSame.out.match(/class="app-row /g) || []).length;
    A(rows === rSame.res.sps.length, `${f}: identical names do not collapse rows (${rows}/${rSame.res.sps.length} apps shown)`);
  }
}

// ---------- 3. spoofing a Microsoft app by name does not earn first-party treatment ----------
{
  const d = JSON.parse(FIXTURES.find(x => x.f === "tenant-fixture-v091.json").raw);
  d.servicePrincipals.find(s => s.id === "sp-1003").displayName = "Office 365 Exchange Online";
  const r = renderAll("tenant", d).res, sp = r.sps.find(s => s.id === "sp-1003");
  const codes = (sp.credFlags || []).map(f => f.code);
  A(codes.includes("xtenant") && !codes.includes("ms-firstparty"),
    "vendor app renamed to a Microsoft app name still gets the vendor cross-tenant flag, not first-party");
}

// ---------- 4. public build input: the paste box only admits knowledge-base ids ----------
{
  run("selected = new Set()");
  els.paste = els.paste || makeEl("paste");
  els.paste.value = PAYLOADS.map(([, mk], i) => mk(`PASTE${i}X`)).join("\n") + "\nRoleManagement.ReadWrite.Directory <img src=x onerror=alert(1)>";
  run("parsePaste()");
  const sel = run("[...selected]");
  const known = new Set(run("PERMISSIONS.map(p=>p.id.toLowerCase()).concat(ROLES.map(r=>r.id.toLowerCase()))"));
  A(sel.length > 0 && sel.every(id => known.has(id)), `single-app paste admits only knowledge-base ids (${sel.join(", ")})`);
}

// ---------- 5. the exported report is inert ----------
{
  const rep = renderAll("tenant", JSON.parse(FIXTURES.find(x => x.f === "tenant-fixture.json").raw)).report;
  A(/script-src 'none'/.test(rep), "exported report CSP forbids all script");
  A(!/<script/i.test(rep) && !/\son[a-z]+\s*=/i.test(rep.replace(/<style[\s\S]*?<\/style>/i, "")), "exported report contains no script and no inline event handlers");
}

console.log(`\n${ok} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

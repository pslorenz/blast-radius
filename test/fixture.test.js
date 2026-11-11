// Fixture-based regression: loads the real fixtures through the actual engine
// (as the browser would), checks verdicts, flags, PascalCase tolerance, and the
// v0.9/v0.9.1 detections. Run: node test/fixture.test.js
//
// Flags are matched on their stable `code`, never on display text, so a copy edit
// can't silently break (or silently pass) an assertion.
const vm = require("vm"); const fs = require("fs"); const path = require("path");
const ROOT = path.join(__dirname, "..");

function makeEl(id){return{id:id||"el",_html:"",dataset:{},style:{},classList:{_s:new Set(),add(c){this._s.add(c)},remove(c){this._s.delete(c)},toggle(c){this._s.has(c)?this._s.delete(c):this._s.add(c)},contains(c){return this._s.has(c)}},hidden:false,tabIndex:0,value:"",textContent:"",files:[],children:[],setAttribute(){},getAttribute(){return null},hasAttribute(){return false},addEventListener(){},appendChild(c){this.children.push(c);return c;},querySelector(){return makeEl()},querySelectorAll(){return[]},closest(){return makeEl()},scrollIntoView(){},focus(){},click(){},remove(){},get innerHTML(){return this._html},set innerHTML(v){this._html=v;}};}
const els={};
const sb={document:{getElementById:id=>els[id]||(els[id]=makeEl(id)),querySelector:()=>null,querySelectorAll:()=>[],addEventListener:(ev,fn)=>{if(ev==="DOMContentLoaded")sb.__init=fn;},createElement:t=>makeEl(t),body:{dataset:{},appendChild(c){return c;},removeChild(){}}},navigator:{clipboard:{writeText:()=>Promise.resolve()}},FileReader:class{readAsText(){this.onload&&this.onload();}},alert:()=>{},setTimeout:fn=>fn(),console,Blob:class{constructor(a){this.parts=a}},URL:{createObjectURL:()=>"blob:x",revokeObjectURL(){}}};
vm.createContext(sb);
vm.runInContext(fs.readFileSync(path.join(ROOT,"kb.js"),"utf8")+"\n"+fs.readFileSync(path.join(ROOT,"app.js"),"utf8"), sb);

const tenant = JSON.parse(fs.readFileSync(path.join(ROOT,"fixtures/tenant-fixture.json"),"utf8"));
const partner = JSON.parse(fs.readFileSync(path.join(ROOT,"fixtures/partner-fixture.json"),"utf8"));

let ok=0, fail=0; const A=(c,m)=>{ (c?ok++:fail++); console.log((c?"PASS":"FAIL")+" "+m); };
const get = (r,id) => r.sps.find(s=>s.id===id);
const hasFlag = (sp, code, sev) => (sp.credFlags||[]).some(f => f.code === code && (!sev || f.sev === sev));
const load = name => JSON.parse(fs.readFileSync(path.join(ROOT,"fixtures",name),"utf8"));

// ---------- TENANT fixture ----------
sb.__tenant = tenant;
const rt = vm.runInContext("analyzeTenant(__tenant)", sb);

A(rt.roll.total === 7, "tenant fixture parses 7 apps ("+rt.roll.total+")");
A(get(rt,"sp-0003").finalSev === "direct", "Legacy Runner (RoleManagement.ReadWrite.Directory) => direct");
A(get(rt,"sp-0002").finalSev === "direct" && get(rt,"sp-0002").confirmedViaChain,
  "Teams Manager (Application.ReadWrite.All) => confirmed via backdoor chain to the privileged app");
A(get(rt,"sp-0001").finalSev === "none", "Backup app (data scopes only) => no known path");
A(hasFlag(get(rt,"sp-0001"), "xtenant", "high"),
  "Backup app (vendor-owned SP with tenant-side secret) => cross-tenant credential HIGH flag");

// PascalCase credential fields (StartDateTime/EndDateTime) parse for long-lived detection
A(hasFlag(get(rt,"sp-0001"), "longlived"),
  "PascalCase credential dates parsed (long-lived secret detected)");

// PIM-eligible distinct state
A(get(rt,"sp-0004").finalSev === "direct" && get(rt,"sp-0004").viaPim === true,
  "JIT Operations (eligible GA only) => direct but PIM-gated");
A(get(rt,"sp-0004").riskScore < get(rt,"sp-0003").riskScore,
  "PIM-gated GA scored below standing-direct ("+get(rt,"sp-0004").riskScore+" < "+get(rt,"sp-0003").riskScore+")");

// ownership: App Lifecycle Bot owns the role-assignable Tier-0 group => reaches GA via group ownership
A(get(rt,"sp-0006").finalSev === "direct" && get(rt,"sp-0006").groupProof,
  "App Lifecycle Bot owns a GA role-assignable group => direct via group ownership");

// human owner of the privileged Legacy Runner surfaced distinctly
A((get(rt,"sp-0003").ownerFindings||[]).some(f=>/Dana Admin/.test(f.text)),
  "human owner (Dana Admin) of privileged app surfaced as distinct finding");

// HR Group Sync: group-write, privileged group is role-assignable => cleared (protected)
A(get(rt,"sp-0007").finalSev === "conditional" && get(rt,"sp-0007").groupCleared,
  "HR Group Sync (Group.ReadWrite.All) => conditional, cleared (privileged group is protected role-assignable)");

// rollup new stats
A(rt.roll.crossTenantCreds >= 1, "rollup counts cross-tenant credential apps ("+rt.roll.crossTenantCreds+")");
A(rt.roll.pimGa === 1, "rollup counts 1 PIM-gated GA app ("+rt.roll.pimGa+")");

// changes-since filter honours the boundary
const rtSince = vm.runInContext("analyzeTenant(__tenant, {since:'2026-10-01'})", sb);
A(hasFlag(get(rtSince,"sp-0001"), "since", "high"),
  "changes-since flags the backup secret created 2026-10-05");
const rtSince2 = vm.runInContext("analyzeTenant(__tenant, {since:'2026-10-10'})", sb);
A(!hasFlag(get(rtSince2,"sp-0001"), "since"),
  "changes-since does not flag the secret when date is after its start");

A(rt.sps.every(sp => (sp.credFlags||[]).every(f => typeof f.code === "string" && f.code)),
  "every credential flag carries a stable code");

// ---------- Windows PowerShell 5.1 export (same tenant, "/Date(ms)/" timestamps) ----------
// v0.9.0 parsed these as NaN, which silently disabled every time-based flag.
sb.__ps51 = load("tenant-fixture-ps51.json");
const r51 = vm.runInContext("analyzeTenant(__ps51, {since:'2026-10-01'})", sb);
A(hasFlag(get(r51,"sp-0001"), "longlived"), "PS 5.1 /Date(ms)/ dates parsed (long-lived secret detected)");
A(hasFlag(get(r51,"sp-0001"), "since", "high"), "PS 5.1 /Date(ms)/ dates honour the changes-since filter");
A(r51.roll.ga === rt.roll.ga && r51.roll.crossTenantCreds === rt.roll.crossTenantCreds,
  "PS 5.1 export yields the same verdicts as the PowerShell 7 export");

// ---------- v0.9.1 export shape (lowercase ISO creds, grants, eligible groups, SP owners) ----------
sb.__v091 = load("tenant-fixture-v091.json");
const r91 = vm.runInContext("analyzeTenant(__v091, {since:'2026-10-10'})", sb);
A(get(r91,"sp-1001").finalSev === "direct" && get(r91,"sp-1001").viaPim === true &&
  get(r91,"sp-1001").pimGroup && get(r91,"sp-1001").pimGroup.id === "grp-elig",
  "Ops Console (member of a PIM-eligible GA role-assignable group) => direct, PIM-gated via group");
A(get(r91,"sp-1005").viaPim !== true,
  "eligibility on a NON-role-assignable group is ignored (cannot carry a directory role)");
A(get(r91,"sp-1005").finalSev === "direct" && get(r91,"sp-1005").gaViaOwnership === true,
  "Deploy Pipeline (service-principal owner of a GA-reaching app) => direct via ownership");
A((get(r91,"sp-1006").ownerFindings||[]).length === 0,
  "an SP owner is a backdoor edge, not a human-owner finding");
A(get(r91,"sp-1002").credFlags.some(f => f.code === "longlived" && /app registration/.test(f.why)),
  "app-registration credential source carried into the flag");
A(hasFlag(get(r91,"sp-1003"), "xtenant", "high") && hasFlag(get(r91,"sp-1003"), "since", "high"),
  "Vendor Mailer: tenant-side cert on a vendor SP, created after the review date");
A(get(r91,"sp-1003").perms.some(p => p.id === "Mail.Send"),
  "delegated grant scopes (oauth2PermissionGrants) resolved into permissions");
A(hasFlag(get(r91,"sp-1004"), "ms-firstparty", "high") && !hasFlag(get(r91,"sp-1004"), "xtenant"),
  "credential on a Microsoft first-party SP => its own HIGH flag, not the generic vendor flag");
A(r91.roll.crossTenantCreds === 2, "rollup counts vendor + Microsoft cross-tenant credentials ("+r91.roll.crossTenantCreds+")");
A(r91.roll.pimGa === 1, "rollup counts the PIM-gated group path ("+r91.roll.pimGa+")");

// client report carries the v0.9 findings (the deliverable a client actually sees)
vm.runInContext("tenantData = analyzeTenant(__v091, {since:'2026-10-10'}); tenantData.since = '2026-10-10';", sb);
const rep = vm.runInContext("buildReportHTML('tenant')", sb);
A(/Content-Security-Policy/.test(rep) && /default-src 'none'/.test(rep), "exported report carries a no-network CSP");
A(/Global Admin \(PIM-gated\)/.test(rep), "report labels PIM-gated verdicts as such");
A(/Credential and ownership findings/.test(rep) && /Review date/.test(rep), "report lists credential/ownership findings and the review date");
A(/owns the more privileged app/.test(rep), "report explains the ownership path");

// ---------- PARTNER fixture (raw Graph shape: accessDetails.unifiedRoles GUIDs) ----------
sb.__partner = partner;
// pin the clock to the export time: relationship expiry is relative to "now", and a wall
// clock turns this frozen fixture into a time bomb (Borealis ends 2026-11-01)
sb.__pnow = Date.parse(partner.generatedAt);
const rp = vm.runInContext("analyzePartner(__partner, {now: __pnow})", sb);
const cust = id => rp.custList.find(c=>c.id===id);
A(rp.roll.customers === 3, "partner fixture parses 3 customers ("+rp.roll.customers+")");
A(cust("cust-acme-0001").sev === "direct", "Acme (GA via GUID role) => full takeover, raw shape resolved");
A(cust("cust-borealis-0002").sev === "conditional", "Borealis (Exchange Admin) => scoped");
A(cust("cust-borealis-0002").relstat === "expiring", "Borealis relationship expiring (<30d) flagged");
const rmm = rp.keyList.find(k=>k.name.includes("RMM"));
A(rmm && rmm.directCount >= 1, "RMM Automation group is a master key (GA into Acme)");
A(rp.roll.noMfaMembers === 1, "1 admin without MFA (Dave) counted");

// ---------- public build engine: tenant/partner code stripped, single-app still works ----------
const STRIP = /\/\/ <<<STRIP-PUBLIC-START>>>[\s\S]*?\/\/ <<<STRIP-PUBLIC-END>>>\n/g;
const pubApp = fs.readFileSync(path.join(ROOT,"app.js"),"utf8").replace(STRIP, "");
// fresh sandbox: copy only the browser stubs, not the globals the full engine defined
const sbPub = {}; ["navigator","FileReader","alert","setTimeout","console","Blob","URL"].forEach(k => sbPub[k] = sb[k]);
sbPub.document = Object.assign({}, sb.document, { addEventListener: () => {} });
vm.createContext(sbPub);
let pubOk = true;
try { vm.runInContext(fs.readFileSync(path.join(ROOT,"kb.js"),"utf8")+"\n"+pubApp, sbPub); } catch (e) { pubOk = false; console.log(e); }
A(pubOk, "public build's engine loads with tenant/partner code stripped");
A(vm.runInContext("typeof analyzeTenant", sbPub) === "undefined" && vm.runInContext("typeof SAMPLE_TENANT", sbPub) === "undefined",
  "public build contains no tenant engine or tenant sample");
A(vm.runInContext("analyzeApp(['RoleManagement.ReadWrite.Directory'].map(resolvePerm), [], 'single-tenant').sev", sbPub) === "direct",
  "public build still classifies a single app (RoleManagement.ReadWrite.Directory => direct)");

// ---------- knowledge base vs azure-tiering snapshot ----------
// A Tier-0 permission missing from the KB is silently dropped ("no known path"),
// the failure this project ranks worst. Snapshots live in test/data and are
// refreshed with scripts/sync_azure_tiering.py; every change there gets reviewed.
const snap = name => { const f = path.join(ROOT, "test", "data", name); return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : null; };
const want = pt => pt === "Direct" ? "direct" : "conditional";   // Indirect and untested/legacy ("n/a") => at least conditional
const atLeast = (have, need) => need === "direct" ? have === "direct" : have === "direct" || have === "conditional";
{
  const g = snap("azure-tiering-graph-tier0.json");
  const kbPerm = id => vm.runInContext(`PERMISSIONS.find(p => p.id === ${JSON.stringify(id)}) || null`, sb);
  const missing = [], wrongGuid = [], tooLow = [];
  g.tier0.forEach(e => {
    const p = kbPerm(e.assetName);
    if (!p) return missing.push(e.assetName);
    if ((p.guid || "").toLowerCase() !== e.id.toLowerCase()) wrongGuid.push(`${e.assetName} (kb ${p.guid}, azure-tiering ${e.id})`);
    if (!atLeast(p.escalation, want(e.pathType))) tooLow.push(`${e.assetName}: kb ${p.escalation}, azure-tiering ${e.pathType}`);
  });
  A(missing.length === 0, `every azure-tiering Graph Tier-0 permission is in the KB (snapshot ${g.snapshot})${missing.map(x => "\n       missing: " + x).join("")}`);
  A(wrongGuid.length === 0, `KB permission GUIDs match azure-tiering${wrongGuid.map(x => "\n       " + x).join("")}`);
  A(tooLow.length === 0, `no KB permission is rated below azure-tiering${tooLow.map(x => "\n       " + x).join("")}`);
  A(g.tier0.every(e => vm.runInContext(`resolvePerm(${JSON.stringify(e.id)})`, sb)),
    "every Tier-0 permission resolves from a GUID-only export");
}
{
  const r = snap("azure-tiering-entra-tier0.json");
  if (!r) console.log("WARN no Entra roles snapshot yet (test/data/azure-tiering-entra-tier0.json): run `py scripts/sync_azure_tiering.py` (python3 on macOS/Linux); roles are NOT checked against azure-tiering");
  else {
    const kbRole = n => vm.runInContext(`ROLES.find(x => x.id.toLowerCase() === ${JSON.stringify(n.toLowerCase())}) || null`, sb);
    const missing = [], unmapped = [], tooLow = [];
    r.tier0.forEach(e => {
      const k = kbRole(e.assetName);
      if (!k) return missing.push(e.assetName);
      if (vm.runInContext(`(resolveRole(${JSON.stringify(e.id)})||{}).id`, sb) !== k.id) unmapped.push(`${e.assetName} (${e.id})`);
      if (!atLeast(k.escalation, want(e.pathType))) tooLow.push(`${e.assetName}: kb ${k.escalation}, azure-tiering ${e.pathType}`);
    });
    A(missing.length === 0, `every azure-tiering Entra Tier-0 role is in the KB (snapshot ${r.snapshot})${missing.map(x => "\n       missing: " + x).join("")}`);
    A(unmapped.length === 0, `every Tier-0 role template ID maps to its KB role${unmapped.map(x => "\n       " + x).join("")}`);
    A(tooLow.length === 0, `no KB role is rated below azure-tiering${tooLow.map(x => "\n       " + x).join("")}`);
  }
}

// ---------- 2026.11.11 KB additions behave in the engine ----------
const variant = mutateFn => { const d = JSON.parse(JSON.stringify(tenant)); mutateFn(d); sb.__var = d; return vm.runInContext("analyzeTenant(__var, {now: Date.parse('2026-10-22T12:00:00Z')})", sb); };
const spOf = (d, id) => d.servicePrincipals.find(s => s.id === id);
{
  const r = variant(d => { spOf(d, "sp-0002").appRoles = ["Application.ReadUpdate.All"]; });
  A(get(r, "sp-0002").finalSev === "direct" && get(r, "sp-0002").confirmedViaChain,
    "Application.ReadUpdate.All plants credentials like Application.ReadWrite.All (confirmed via chain)");
}
{
  const single = ps => vm.runInContext(`analyzeApp(${JSON.stringify(ps)}.map(resolvePerm), [], 'multi-tenant')`, sb);
  A(single(["UserAuthMethod-TAP.ReadWrite.All"]).sev === "direct", "a TAP-only app is a direct path, not 'no known path'");
  A(single(["DelegatedAdminRelationship.ReadWrite.All"]).sev === "direct", "DelegatedAdminRelationship.ReadWrite.All is a direct (cross-tenant) path");
  A(vm.runInContext("isLockoutOnly", sb)(single(["User.DeleteRestore.All"])), "User.DeleteRestore.All alone is a lockout, not a GA path");
  A(!vm.runInContext("isLockoutOnly", sb)(single(["User.DeleteRestore.All", "RoleManagement.ReadWrite.Directory"])),
    "lockout plus a real GA permission is a GA path");
}
{
  const r = variant(d => { spOf(d, "sp-0005").appRoles.push("Policy.ReadWrite.ConditionalAccess"); });
  A(get(r, "sp-0005").finalSev === "direct" && get(r, "sp-0005").lockoutOnly === true, "Conditional Access writer => lockout, labeled as such");
  A(r.roll.lockout === 1 && r.roll.ga === rt.roll.ga, `rollup counts lockout separately from GA (ga ${r.roll.ga}, lockout ${r.roll.lockout})`);
  A(get(r, "sp-0002").lockoutOnly === false, "an app that can backdoor both a lockout app and a GA app is a GA path");
}
{
  // a backdoor whose only privileged target is a lockout app inherits the lockout, not GA
  const r = variant(d => {
    d.servicePrincipals = d.servicePrincipals.filter(s => ["sp-0002", "sp-0005"].includes(s.id));
    spOf(d, "sp-0005").appRoles = ["User.EnableDisableAccount.All", "User.Read.All"];
    d.groups = [];
  });
  A(get(r, "sp-0002").finalSev === "direct" && get(r, "sp-0002").lockoutOnly === true,
    "backdooring a lockout-only app is reported as a lockout, not as reaching Global Admin");
}
{
  const r = variant(d => { const sp = spOf(d, "sp-0006"); sp.directoryRoles = ["d29b2b05-8046-44ba-8758-1e26182fcf32"]; });
  A(get(r, "sp-0006").roleObjs.some(x => x.id === "Directory Synchronization Accounts"), "Directory Synchronization Accounts resolves from its template ID");
  A(!get(r, "sp-0006").canModAll, "Directory Synchronization Accounts is no longer treated as able to plant app credentials");
}

// ---------- engine edges come from the KB, not from names in app.js ----------
{
  const src = fs.readFileSync(path.join(ROOT, "app.js"), "utf8");
  const engine = src.slice(0, src.indexOf("const SCRIPT_TEXT"));   // export scripts and samples follow
  const hits = engine.match(/(\.has\(|===\s*|\.includes\()"[A-Z][A-Za-z]+(?:[.-][A-Za-z]+)+"/g) || [];
  A(hits.length === 0, `engine code names no specific permission or role (use KB fields)${hits.map(h => "\n       " + h).join("")}`);
  const allowed = { plantsCredentials: ["any", "owned"], selfEscalates: [true], writesOpenGroups: [true], impact: ["availability"] };
  const bad = vm.runInContext("PERMISSIONS.concat(ROLES)", sb).flatMap(x =>
    Object.keys(allowed).filter(f => f in x && !allowed[f].includes(x[f])).map(f => `${x.id}.${f}=${x[f]}`));
  const noTid = vm.runInContext("ROLES.filter(r => !r.templateId).map(r => r.id)", sb);
  A(noTid.length === 0, `every KB role carries its template ID${noTid.map(x => "\n       " + x).join("")}`);
  A(bad.length === 0, `KB edge fields use known values${bad.map(b => "\n       " + b).join("")}`);
}
{
  const r = variant(d => { spOf(d, "sp-0005").appRoles = ["Policy.ReadWrite.PermissionGrant"]; });
  A(get(r, "sp-0005").finalSev === "direct", "Policy.ReadWrite.PermissionGrant self-escalates in tenant mode (grants itself RoleManagement)");
  const r2 = variant(d => { spOf(d, "sp-0005").appRoles = ["PrivilegedAssignmentSchedule.ReadWrite.EntraAppRole"]; });
  A(get(r2, "sp-0005").finalSev === "direct", "PrivilegedAssignmentSchedule.ReadWrite.EntraAppRole self-escalates in tenant mode");
  const r3 = variant(d => { spOf(d, "sp-0005").appRoles = ["User.Read.All"]; spOf(d, "sp-0005").directoryRoles = ["4ba39ca4-527c-499a-b93d-d9b492c50246"]; });
  A(get(r3, "sp-0005").finalSev === "direct" && get(r3, "sp-0005").confirmedViaChain, "Partner Tier1 Support plants app credentials (confirmed via chain)");
  // Application Administrator is Indirect (conditional) on its own; tenant mode confirms the chain
  const withApp = variant(d => { const sp = spOf(d, "sp-0005"); sp.appRoles = ["User.Read.All"]; sp.directoryRoles = ["9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"]; });
  A(get(withApp, "sp-0005").finalSev === "direct" && get(withApp, "sp-0005").confirmedViaChain,
    "Application Administrator => direct when the tenant has a privileged app to backdoor (confirmed via chain)");
  const noTarget = variant(d => {
    d.servicePrincipals = d.servicePrincipals.filter(s => s.id === "sp-0005"); d.groups = [];
    const sp = spOf(d, "sp-0005"); sp.appRoles = ["User.Read.All"]; sp.directoryRoles = ["9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"];
  });
  A(get(noTarget, "sp-0005").finalSev === "conditional", "Application Administrator => conditional when no privileged app exists to backdoor");
  const role = n => vm.runInContext(`analyzeApp([], [resolveRole(${JSON.stringify(n)})], 'multi-tenant')`, sb);
  A(vm.runInContext("isLockoutOnly", sb)(role("Conditional Access Administrator")), "Conditional Access Administrator is a lockout, labeled as such");
  A(vm.runInContext("isLockoutOnly", sb)(role("Security Administrator")) && role("Security Administrator").sev === "direct", "Security Administrator: direct, lockout-labeled");
  A(role("Tenant Governance Administrator").sev === "direct" && !vm.runInContext("isLockoutOnly", sb)(role("Tenant Governance Administrator")), "Tenant Governance Administrator is a real Global Admin path");
}

// ---------- v0.9.2: modes agree; gaps that switch checks off are surfaced ----------
{
  const self = vm.runInContext("PERMISSIONS.filter(p => p.selfEscalates).map(p => p.id)", sb);
  const disagree = self.filter(id => {
    const single = vm.runInContext(`analyzeApp([resolvePerm(${JSON.stringify(id)})], [], 'multi-tenant').sev`, sb);
    const r = variant(d => { spOf(d, "sp-0005").appRoles = [id]; });
    return single !== "direct" || get(r, "sp-0005").finalSev !== "direct";
  });
  A(self.length >= 3 && disagree.length === 0, `self-escalating permissions are direct in both single-app and tenant mode (${self.length})${disagree.map(x => "\n       " + x).join("")}`);
}
{
  const r = variant(d => { delete d.tenantId; });
  A(r.warnings.some(w => w.code === "no-tenant-id"), "an export without tenantId carries a no-tenant-id warning");
  A(variant(() => {}).warnings.length === 0, "a complete export carries no warnings");
  sb.__noTid = r; vm.runInContext("tenantData = __noTid", sb);
  const rep2 = vm.runInContext("buildReportHTML('tenant')", sb);
  A(/Check not run\./.test(rep2) && /no tenantId/.test(rep2), "the report states that the cross-tenant checks did not run");
}

console.log(`\n${ok} passed, ${fail} failed`);
process.exit(fail?1:0);

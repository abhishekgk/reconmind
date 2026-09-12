"use strict";
// ReconMind front-end. Plain vanilla JS, no build step — easy to read and hack on.

const $ = (id) => document.getElementById(id);

// ---------- auth (only active when the server requires it) ----------
const _origFetch = window.fetch.bind(window);
let AUTH_REQUIRED=false, ALLOW_REG=false, authMode="login", _appStarted=false;
// Catch session-expiry 401s from any API call and pop the login overlay.
window.fetch = async (...args) => {
  const res = await _origFetch(...args);
  try{
    const url=(typeof args[0]==="string"?args[0]:(args[0]&&args[0].url))||"";
    if(res.status===401 && url.includes("/api/") && !url.includes("/api/auth/")) showLogin("Your session expired — please sign in again.");
  }catch(e){}
  return res;
};

let currentScanId = null;
let scanData = null;
let elapsedTimer = null, startTs = null, pollTimer = null;
let activeTab = "subs";
let priorHosts = new Set();  // hosts from the previous scan of this domain (for "new" badges)
const SORT = {
  subs:{k:"live",d:-1}, ips:{k:"ip",d:1}, asns:{k:"asn",d:1},
  endpoints:{k:"host",d:1}, takeovers:{k:"confidence",d:1}, related:{k:"domain",d:1},
  findings:{k:"severity",d:1},
};
const facet = { status:new Set(), epStatus:new Set(), findType:new Set(), shot:false, takeover:false, newOnly:false, hideRev:false };

const INTERESTING = /(^|[.\-])(dev|test|stage|staging|uat|qa|sandbox|internal|intranet|corp|admin|api|graphql|gateway|auth|sso|login|jenkins|gitlab|git|jira|grafana|kibana|vpn|legacy|old|beta|backup|s3|storage|preprod|demo)([.\-]|$)/i;

function esc(s){ return (s||"").replace(/[<>&"]/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;"}[c])); }
function statusClass(s){ if(s==null)return""; if(s<300)return"ok"; if(s<400)return"redir"; if(s<500)return"cli"; return"srv"; }

// ---------- per-asset notes (localStorage) ----------
let NOTES = {};
try{ NOTES = JSON.parse(localStorage.getItem("reconmind_notes")||"{}"); }catch(e){ NOTES={}; }
function noteKey(host){ return (scanData?scanData.domain:"")+"::"+host; }
function getNote(host){ return NOTES[noteKey(host)] || {reviewed:false, note:""}; }
function setNote(host, patch){
  const k=noteKey(host); NOTES[k]=Object.assign(getNote(host), patch);
  if(!NOTES[k].reviewed && !NOTES[k].note) delete NOTES[k];
  localStorage.setItem("reconmind_notes", JSON.stringify(NOTES));
}

// ---------- toolbox + llm ----------
async function loadTools(){
  const t = await (await fetch("/api/tools")).json();
  $("toolbox").innerHTML = t.tools.map(x=>`
    <div class="toolrow" title="${esc(x.purpose)}\n${x.available?esc(x.path):esc(x.install)}">
      <span>${x.available?'<span class="ok-dot">●</span>':'<span class="no-dot">○</span>'} ${x.name}</span>
      <span class="muted">${x.available?'ready':'missing'}</span></div>`).join("");
}
async function loadLlm(){
  const s = await (await fetch("/api/llm/status")).json();
  if(s.provider==="claude") $("llmStatus").innerHTML = `LLM: <b style="color:var(--accent)">Claude ${esc(s.model)}</b>`;
  else if(s.available && s.model) $("llmStatus").innerHTML = `LLM: <b style="color:var(--accent)">${esc(s.model)}</b> (local)${s.claude_configured?"":' · <span class="muted">add Anthropic key for better answers</span>'}`;
  else if(s.available) $("llmStatus").innerHTML = `LLM: local, no model — <code>ollama pull llama3.1</code>`;
  else $("llmStatus").innerHTML = `LLM: local offline — <code>ollama serve</code> or add an Anthropic key`;
}

// ---------- model picker ----------
async function loadModels(){
  try{
    const d = await (await fetch("/api/llm/models")).json();
    const sel = $("modelSelect");
    sel.innerHTML = (d.models||[]).map(m=>`<option value="${esc(m.id)}">${esc(m.label)}</option>`).join("");
    sel.value = d.current || "auto";
    if(!(d.models||[]).some(m=>m.id===sel.value)) sel.value="auto";
  }catch(e){}
}
async function onModelChange(){
  const model = $("modelSelect").value;
  try{
    await fetch("/api/llm/model",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model})});
  }catch(e){}
  loadLlm();  // refresh the status badge to reflect the new choice
}

// ---------- API keys modal ----------
async function openKeys(){
  const data = await (await fetch("/api/keys/specs")).json();
  $("keyList").innerHTML = data.services.map(s=>`
    <div class="keyitem" data-id="${s.id}">
      <div class="khead">
        <span><span class="kname">${esc(s.label)}</span>
          <span class="knote">— ${esc(s.note)}${s.feeds_subfinder?' · feeds subfinder':''}</span></span>
        <span style="display:flex;gap:8px;align-items:center">
          <span class="badge ${s.configured?'on':''}">${s.configured?'✓ saved':'not set'}</span>
          ${s.configured?`<a href="#" class="knote" data-remove="${s.id}" style="color:var(--bad)">remove</a>`:''}
        </span></div>
      <div class="kfields">
        ${s.fields.map(f=>`<input type="password" autocomplete="off" data-field="${f.name}"
           placeholder="${s.configured?'saved — leave blank to keep':esc(f.label)}">`).join("")}
      </div>
      <div class="knote" style="margin-top:6px">get a key: <a href="${esc(s.get_url)}" target="_blank" rel="noopener">${esc(s.get_url)}</a></div>
    </div>`).join("");
  document.querySelectorAll("[data-remove]").forEach(a=>a.onclick=(e)=>{ e.preventDefault(); removeKey(a.dataset.remove); });
  $("keysOverlay").classList.add("show");
}
async function removeKey(id){
  await fetch("/api/keys",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({keys:{}, remove:[id]})});
  await openKeys();
}
async function saveKeys(){
  const keys = {};
  document.querySelectorAll(".keyitem").forEach(item=>{
    const id=item.dataset.id, vals={}; let any=false;
    item.querySelectorAll("input[data-field]").forEach(inp=>{ if(inp.value.trim()){ vals[inp.dataset.field]=inp.value.trim(); any=true; } });
    if(any) keys[id]=vals;
  });
  $("keysSave").disabled=true; $("keysSave").textContent="Saving…";
  const r = await (await fetch("/api/keys",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({keys})})).json();
  $("keysSave").disabled=false; $("keysSave").textContent="Save & apply";
  if(r.ok) await openKeys();
}

// ---------- import + history ----------
function importFileChosen(ev){
  const file=ev.target.files[0]; if(!file) return;
  const reader=new FileReader();
  reader.onload=async ()=>{
    let data; try{ data=JSON.parse(reader.result); }catch(e){ alert("That file isn't valid JSON."); return; }
    const r=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});
    if(!r.ok){ const e=await r.json().catch(()=>({})); alert(e.detail||"Import failed."); return; }
    const res=await r.json(); applyScan(res.id,res.data); $("phase").textContent=`✓ imported ${res.data.domain||"scan"}`;
  };
  reader.readAsText(file); ev.target.value="";
}
let HIST_SCANS = [];
async function openHistory(){
  try{ HIST_SCANS = (await (await fetch("/api/scans")).json()).scans||[]; }
  catch(e){ HIST_SCANS=[]; }
  renderHistoryList();
  $("historyOverlay").classList.add("show");
}
function histInRange(s, range){
  if(range==="all") return true;
  const now=Date.now()/1000, day=86400;
  if(!s.finished) return range==="older";          // undated scans count as "old"
  const age=now-s.finished;
  if(range==="today"){ const d=new Date(); d.setHours(0,0,0,0); return s.finished>=d.getTime()/1000; }
  if(range==="7d")   return age<=7*day;
  if(range==="30d")  return age<=30*day;
  if(range==="older") return age>30*day;
  return true;
}
function renderHistoryList(){
  const range=$("histRange")?$("histRange").value:"all";
  const order=$("histOrder")?$("histOrder").value:"new";
  const q=($("histSearch")?$("histSearch").value:"").trim().toLowerCase();
  let scans=HIST_SCANS.filter(s=>histInRange(s,range));
  if(q) scans=scans.filter(s=>(s.domain||"").toLowerCase().includes(q));
  scans=scans.slice().sort((a,b)=>{ const av=a.finished||0, bv=b.finished||0; return order==="old"?av-bv:bv-av; });
  $("histShowing").textContent=`${scans.length} of ${HIST_SCANS.length} scans`;
  $("historyList").innerHTML = HIST_SCANS.length ? (scans.length ? scans.map(s=>{
    const c=s.counts||{}, when=s.finished?new Date(s.finished*1000).toLocaleString():"undated";
    return `<div class="histrow"><div><div class="hd">${esc(s.domain||"?")}</div>
      <div class="hc">${esc(when)} · ${c.total||0} subs · ${c.live||0} live · ${c.ips||0} IPs · ${c.endpoints||0} endpoints · ${c.takeovers||0} takeovers</div></div>
      <div style="display:flex;gap:8px">
        <button class="ghost sm" data-load="${esc(s.file)}">Load</button>
        <button class="ghost sm" data-del="${esc(s.file)}" title="delete this saved scan" style="color:var(--bad)">🗑</button>
      </div></div>`; }).join("")
    : `<p class="muted">No scans match this filter.</p>`)
    : `<p class="muted">No saved scans yet.</p>`;
  document.querySelectorAll("[data-load]").forEach(b=>b.onclick=()=>loadHistory(b.dataset.load));
  document.querySelectorAll("[data-del]").forEach(b=>b.onclick=()=>deleteScan(b.dataset.del));
}
async function deleteScan(file){
  const s=HIST_SCANS.find(x=>x.file===file);
  if(!confirm(`Delete this saved scan?\n\n${(s&&s.domain)||file}\n${s&&s.finished?new Date(s.finished*1000).toLocaleString():""}\n\nThis removes the JSON file from ~/.reconmind/data and can't be undone.`)) return;
  try{
    const r=await fetch(`/api/scans/${encodeURIComponent(file)}`,{method:"DELETE"});
    if(!r.ok){ alert("Could not delete that scan."); return; }
    HIST_SCANS=HIST_SCANS.filter(x=>x.file!==file);
    renderHistoryList();
  }catch(e){ alert("Could not delete that scan."); }
}
async function loadHistory(file){
  const r=await fetch(`/api/scans/${encodeURIComponent(file)}/load`,{method:"POST"});
  if(!r.ok){ alert("Could not load that scan."); return; }
  const res=await r.json(); applyScan(res.id,res.data); $("historyOverlay").classList.remove("show");
  $("phase").textContent=`✓ loaded ${res.data.domain||"scan"}`;
}

// ---------- scanning + live streaming ----------
function fmtElapsed(){ return startTs?Math.round((Date.now()-startTs)/1000)+"s":"0s"; }
function resetBtn(){ $("scanBtn").disabled=false; $("scanBtn").textContent="Start recon"; clearInterval(elapsedTimer); clearInterval(pollTimer); }
function startScan(){
  const domain=$("domain").value.trim(); if(!domain){ $("domain").focus(); return; }
  $("scanBtn").disabled=true; $("scanBtn").textContent="Scanning…";
  $("phase").textContent="starting…"; $("sourcePills").innerHTML=""; $("panel").innerHTML="";
  ["cTotal","cLive","cIps","cAsns","cRelated","cEndpoints","cTakeovers"].forEach(id=>$(id).textContent="0");
  for(const k in sourcePills) delete sourcePills[k];
  startTs=Date.now(); clearInterval(elapsedTimer);
  elapsedTimer=setInterval(()=>$("cElapsed").textContent=fmtElapsed(),1000);
  fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({domain, active:$("active").checked, deep:$("deep").checked, crawl:$("crawl").checked})})
    .then(r=>r.json()).then(res=>{
      if(res.detail){ alert(res.detail); resetBtn(); return; }
      currentScanId=res.id; listen(res.id);
      // Live streaming: poll partial results every 4s while the scan runs.
      clearInterval(pollTimer);
      pollTimer=setInterval(()=>{ if(currentScanId) fetch(`/api/scan/${currentScanId}`).then(r=>r.json()).then(d=>{ if(d && d.status==="running") applyScan(currentScanId,d,true); }).catch(()=>{}); }, 4000);
    }).catch(()=>{ alert("Failed to start scan"); resetBtn(); });
}
const sourcePills={};
function listen(id){
  const es=new EventSource(`/api/scan/${id}/events`);
  es.onmessage=(e)=>{
    const ev=JSON.parse(e.data);
    if(ev.kind==="phase") $("phase").textContent="▸ "+ev.phase;
    if(ev.kind==="source_done"){ sourcePills[ev.source]=ev.count; renderPills(); $("cTotal").textContent=ev.total; }
    if(ev.kind==="live") $("cLive").textContent=ev.count;
    if(ev.kind==="network"){ $("cIps").textContent=ev.ips; $("cAsns").textContent=ev.asns; }
    if(ev.kind==="endpoints") $("cEndpoints").textContent=ev.count;
    if(ev.kind==="takeovers") $("cTakeovers").textContent=ev.count;
    if(ev.kind==="done"||ev.kind==="error"){ es.close(); resetBtn();
      $("phase").textContent=ev.kind==="error"?"⚠ "+(ev.message||"error"):"✓ scan complete"; refresh(id); }
  };
  es.onerror=()=>{ es.close(); resetBtn(); refresh(id); };
}
function renderPills(){
  $("sourcePills").innerHTML=Object.entries(sourcePills).sort((a,b)=>b[1]-a[1])
    .map(([k,v])=>`<span class="pill${v===0?' zero':''}" ${v===0?'title="0 found — may be rate-limited during a big scan, or no data for this target"':''}>${esc(k)} <b>${v}</b></span>`).join("");
}
async function refresh(id){ const data=await (await fetch(`/api/scan/${id}`)).json(); applyScan(id,data); }
// Quietly re-pull the loaded scan (e.g. after Fuzzer/Nuclei saved findings into it)
// so the Findings count + tab update without leaving the current tab.
async function refreshFindings(){ if(!currentScanId) return; try{ const d=await (await fetch(`/api/scan/${currentScanId}`)).json(); if(d && !d.detail) applyScan(currentScanId,d,true); }catch(e){} }

function applyScan(id, data, partial){
  currentScanId=id; scanData=data;
  const c=data.counts||{};
  $("cTotal").textContent=c.total||0; $("cLive").textContent=c.live||0;
  $("cIps").textContent=c.ips||0; $("cAsns").textContent=c.asns||0;
  $("cRelated").textContent=c.related||0; $("cEndpoints").textContent=c.endpoints||0;
  $("cTakeovers").textContent=c.takeovers||0; $("cFindings").textContent=c.findings||0;
  $("tSubs").textContent=c.total||0; $("tIps").textContent=c.ips||0; $("tAsns").textContent=c.asns||0;
  $("tEndpoints").textContent=c.endpoints||0; $("tTakeovers").textContent=c.takeovers||0; $("tRelated").textContent=c.related||0;
  $("tFindings").textContent=c.findings||0;
  render();
  if(!partial) computeDiff(data);  // fetch prior scan for "new" badges (once, on final)
}

// ---------- scan diff (new since last scan) ----------
async function computeDiff(data){
  priorHosts = new Set();
  try{
    const list=(await (await fetch("/api/scans")).json()).scans||[];
    const prior=list.find(s=>s.domain===data.domain && s.finished && s.finished!==data.finished);
    if(!prior) return;
    const pd=await (await fetch(`/api/scans/${encodeURIComponent(prior.file)}`)).json();
    priorHosts=new Set((pd.hosts||[]).map(h=>h.host));
    if(activeTab==="subs") renderSubs();
  }catch(e){}
}

// ---------- tabs + generic table ----------
function render(){
  const custom = activeTab==="fuzzer" || activeTab==="nuclei";
  $("filterbar").style.display = custom ? "none" : "";
  $("facets").style.display    = custom ? "none" : "";
  if(activeTab==="fuzzer"){ renderFuzzer(); return; }
  if(activeTab==="nuclei"){ renderNuclei(); return; }
  if(!scanData){ $("panel").innerHTML=""; return; }
  $("liveWrap").style.display   = activeTab==="subs" ? "flex" : "none";
  $("paramsWrap").style.display = activeTab==="endpoints" ? "flex" : "none";
  renderFacets();
  if(activeTab==="subs") renderSubs();
  else if(activeTab==="ips") renderIps();
  else if(activeTab==="asns") renderAsns();
  else if(activeTab==="endpoints") renderEndpoints();
  else if(activeTab==="takeovers") renderTakeovers();
  else if(activeTab==="related") renderRelated();
  else if(activeTab==="findings") renderFindings();
}
function filterText(){ return $("filter").value.trim().toLowerCase(); }
function renderTable(tab, cols, rows, total, cap){
  const st=SORT[tab];
  // Global negative filter (comma-separated): hide rows matching any term.
  const exq=(($("exclude")&&$("exclude").value)||"").trim();
  if(exq){ const terms=exq.split(",").map(s=>s.trim().toLowerCase()).filter(Boolean);
    if(terms.length) rows=rows.filter(r=>{ const blob=cols.map(c=>c.val?String(c.val(r)):"").join(" ").toLowerCase(); return !terms.some(t=>blob.includes(t)); }); }
  if(!cols.find(c=>c.key===st.k && !c.nosort)){ const f=cols.find(c=>!c.nosort); st.k=f?f.key:cols[0].key; }
  const col=cols.find(c=>c.key===st.k)||cols[0];
  const sorted=rows.slice().sort((x,y)=>{ let a=col.val(x),b=col.val(y); if(a==null)a="";if(b==null)b="";
    let r; if(typeof a==="number"&&typeof b==="number")r=a-b; else{a=String(a).toLowerCase();b=String(b).toLowerCase();r=a<b?-1:(a>b?1:0);} return r*st.d; });
  const shown=cap?sorted.slice(0,cap):sorted;
  $("showing").textContent=`showing ${shown.length} / ${total}`;
  const head=cols.map(c=>{ if(c.nosort) return `<th></th>`;
    const arr=st.k===c.key?(st.d>0?' <span style="color:var(--accent2)">▲</span>':' <span style="color:var(--accent2)">▼</span>'):'';
    return `<th data-col="${esc(c.key)}" style="cursor:pointer;white-space:nowrap">${esc(c.label)}${arr}</th>`; }).join("");
  const body=shown.map(r=>`<tr class="${col.rowcls?col.rowcls(r):''}">`+cols.map(c=>c.cell(r)).join("")+"</tr>").join("");
  const note=(cap&&sorted.length>cap)?`<p class="muted">Showing first ${cap} of ${sorted.length} — refine the filter.</p>`:"";
  $("panel").innerHTML=`<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>${note}`;
  document.querySelectorAll("th[data-col]").forEach(th=>th.onclick=()=>{ const k=th.dataset.col; if(st.k===k)st.d*=-1; else{st.k=k;st.d=1;} render(); });
}

// ---------- facets (subdomains tab) ----------
function epBucket(s){ return s==null?"none":Math.floor(s/100)+"xx"; }
function renderFacets(){
  const f=$("facets");
  const chip=(id,label,on)=>`<span class="facet ${on?'on':''}" data-facet="${id}">${label}</span>`;
  if(activeTab==="subs"){
    f.innerHTML = ["2xx","3xx","4xx","5xx"].map(s=>chip("status:"+s,s,facet.status.has(s))).join("")
      + chip("shot","📷 has shot",facet.shot) + chip("takeover","⚠ takeover",facet.takeover)
      + chip("new","🆕 new",facet.newOnly) + chip("hiderev","hide reviewed",facet.hideRev);
  } else if(activeTab==="endpoints"){
    const all=scanData.endpoints||[];
    if(!all.length){ f.innerHTML=""; return; }
    const n=(b)=>all.filter(r=>epBucket(r.status)===b).length;
    f.innerHTML = ["2xx","3xx","4xx","5xx"].map(s=>chip("ep:"+s,`${s} <b>${n(s)}</b>`,facet.epStatus.has(s))).join("")
      + chip("ep:none",`∅ unknown <b>${n("none")}</b>`,facet.epStatus.has("none"));
  } else if(activeTab==="findings"){
    const all=findingRows();
    if(!all.length){ f.innerHTML=""; return; }
    const n=(t)=>all.filter(r=>r._t===t).length;
    f.innerHTML = ["nuclei","exposure","fuzz","param","vhost"].map(t=>n(t)?chip("ft:"+t,`${t} <b>${n(t)}</b>`,facet.findType.has(t)):"").join("");
  } else { f.innerHTML=""; return; }
  f.querySelectorAll("[data-facet]").forEach(el=>el.onclick=()=>{
    const id=el.dataset.facet;
    if(id.startsWith("status:")){ const s=id.slice(7); facet.status.has(s)?facet.status.delete(s):facet.status.add(s); }
    else if(id.startsWith("ep:")){ const s=id.slice(3); facet.epStatus.has(s)?facet.epStatus.delete(s):facet.epStatus.add(s); }
    else if(id.startsWith("ft:")){ const s=id.slice(3); facet.findType.has(s)?facet.findType.delete(s):facet.findType.add(s); }
    else if(id==="shot") facet.shot=!facet.shot;
    else if(id==="takeover") facet.takeover=!facet.takeover;
    else if(id==="new") facet.newOnly=!facet.newOnly;
    else if(id==="hiderev") facet.hideRev=!facet.hideRev;
    render();
  });
}
function statusBucket(s){ if(s==null)return null; return Math.floor(s/100)+"xx"; }

function renderSubs(){
  let rows=scanData.hosts.slice();
  if($("onlyLive").checked) rows=rows.filter(r=>r.live);
  if(facet.status.size) rows=rows.filter(r=>facet.status.has(statusBucket(r.status)));
  if(facet.shot) rows=rows.filter(r=>r.screenshot);
  if(facet.takeover) rows=rows.filter(r=>r.takeover);
  if(facet.newOnly) rows=rows.filter(r=>priorHosts.size && !priorHosts.has(r.host));
  if(facet.hideRev) rows=rows.filter(r=>!getNote(r.host).reviewed);
  const f=filterText();
  if(f) rows=rows.filter(r=>r.host.includes(f)||(r.title||"").toLowerCase().includes(f)||(r.server||"").toLowerCase().includes(f)||(r.tech||[]).join(" ").toLowerCase().includes(f)||(r.sources||[]).join(",").includes(f));
  const cols=[
    {key:"rev",label:"",nosort:true,cell:r=>{const n=getNote(r.host);return `<td><span class="revbtn ${n.reviewed?'on':''}" title="mark reviewed" onclick="toggleRev('${esc(r.host)}',this)">✓</span></td>`;}},
    {key:"host",label:"Host",val:r=>r.host,rowcls:r=>getNote(r.host).reviewed?'reviewed':'',cell:r=>{
      const inter=INTERESTING.test(r.host);
      const isnew=priorHosts.size&&!priorHosts.has(r.host)?'<span class="newbadge">NEW</span>':'';
      const host=inter?`<span class="interesting" title="commonly interesting">★ ${esc(r.host)}</span>`:esc(r.host);
      return `<td class="host">${host}${isnew}</td>`;}},
    {key:"shot",label:"",nosort:true,cell:r=>r.screenshot?`<td><img class="thumb" loading="lazy" src="/shots/${esc(r.screenshot)}" onclick="openLight('/shots/${esc(r.screenshot)}')"></td>`:`<td></td>`},
    {key:"live",label:"Live",val:r=>r.live?1:0,cell:r=>`<td>${r.live?'<span class="st ok">●</span>':'<span class="muted">–</span>'}</td>`},
    {key:"status",label:"Status",val:r=>r.status||0,cell:r=>`<td>${r.status?`<span class="st ${statusClass(r.status)}">${r.status}</span>`:''}</td>`},
    {key:"title",label:"Title",val:r=>r.title||"",cell:r=>`<td>${esc(r.title)}</td>`},
    {key:"tech",label:"Tech / Server",val:r=>(r.tech||[]).join(",")||r.server||"",cell:r=>`<td class="muted">${(r.tech||[]).slice(0,4).map(t=>`<span class="tag">${esc(t)}</span>`).join("")}${r.cdn?`<span class="tag">cdn:${esc(r.cdn)}</span>`:""} ${esc(r.server||"")}</td>`},
    {key:"takeover",label:"Takeover",val:r=>r.takeover?(r.takeover.confidence==="high"?2:1):0,cell:r=>r.takeover?`<td><span class="tobadge ${r.takeover.confidence}">${esc(r.takeover.service)}</span></td>`:`<td></td>`},
    {key:"act",label:"",nosort:true,cell:r=> (r.live&&r.url)?`<td style="white-space:nowrap"><button class="ghost sm" title="Fuzz this host" onclick="pivotFuzz('${esc(r.url)}')">🎯</button> <button class="ghost sm" title="Nuclei this host" onclick="pivotNuclei('${esc(r.url)}')">☢</button></td>`:`<td></td>`},
    {key:"note",label:"Note",nosort:true,cell:r=>`<td><input class="notein" value="${esc(getNote(r.host).note)}" placeholder="…" onchange="saveNote('${esc(r.host)}',this.value)"></td>`},
  ];
  renderTable("subs", cols, rows, scanData.hosts.length);
}
window.toggleRev=(host,el)=>{ const n=getNote(host); setNote(host,{reviewed:!n.reviewed}); el.classList.toggle("on"); el.closest("tr").classList.toggle("reviewed"); };
window.saveNote=(host,val)=>setNote(host,{note:val});
window.openLight=(src)=>{ $("lightboxImg").src=src; $("lightbox").classList.add("show"); };

// ---------- cross-tool pivots (send a target from one tab into another) ----------
function pivotFuzz(url){
  if(!url) return;
  FUZZ.url=url; selectTab("fuzzer");
  const el=$("fzUrl"); if(el){ el.value=url; el.focus(); }
  window.scrollTo(0,0); $("phase") && ($("phase").textContent=`▸ sent ${url} to the Fuzzer — add a FUZZ point (or leave it) and Start`);
}
function pivotNuclei(url){
  if(!url) return;
  const cur=(NUKE.targets||"").trim();
  NUKE.targets = cur && cur.split(/\s+/).indexOf(url)<0 ? (cur+"\n"+url) : (cur||url);
  selectTab("nuclei");
  const el=$("nkTargets"); if(el) el.value=NUKE.targets;
  window.scrollTo(0,0);
}
function reportSnippet(r){
  // A ready-to-paste Markdown line for a finding row.
  const sev=(r.severity||"").toUpperCase();
  const label=r.label||r.template||r.type||"";
  const bits=[sev&&`**${sev}**`, label&&`\`${label}\``, r.name, r.url&&`— ${r.url}`].filter(Boolean);
  return "- "+bits.join(" ");
}
function copyReport(text, el){
  const done=()=>{ if(el){ const t=el.textContent; el.textContent="✓"; setTimeout(()=>el.textContent=t,900); } };
  if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).then(done).catch(()=>{ prompt("Copy this:", text); }); }
  else prompt("Copy this:", text);
}
window.pivotFuzz=pivotFuzz; window.pivotNuclei=pivotNuclei;
window.copyFinding=(enc,el)=>copyReport(decodeURIComponent(enc), el);

function renderIps(){
  const all=scanData.ip_assets||[];
  if(!all.length){ $("showing").textContent=""; $("panel").innerHTML=`<p class="muted">No IP data. IPs map to ASNs after resolution; ports come from naabu (deep) or a Shodan key.</p>`; return; }
  let rows=all.slice(); const f=filterText();
  if(f) rows=rows.filter(r=>r.ip.includes(f)||(r.org||"").toLowerCase().includes(f)||("as"+r.asn).includes(f)||(r.ptr||"").toLowerCase().includes(f)||(r.ports||[]).join(",").includes(f));
  const cols=[
    {key:"ip",label:"IP",val:r=>r.ip.split(".").map(n=>n.padStart(3,"0")).join("."),cell:r=>`<td class="mono">${esc(r.ip)}</td>`},
    {key:"asn",label:"ASN",val:r=>parseInt(r.asn)||0,cell:r=>`<td class="mono">${r.asn?'AS'+esc(r.asn):''}</td>`},
    {key:"org",label:"Org",val:r=>r.org||"",cell:r=>`<td class="muted">${esc(r.org)}</td>`},
    {key:"prefix",label:"Netblock",val:r=>r.prefix||"",cell:r=>`<td class="mono muted">${esc(r.prefix)}</td>`},
    {key:"ptr",label:"PTR",val:r=>r.ptr||"",cell:r=>`<td class="mono muted">${esc(r.ptr)}</td>`},
    {key:"ports",label:"Open ports / services",val:r=>(r.ports||[]).length,cell:r=>`<td>${(r.ports||[]).map(p=>`<span class="port">${p}</span>`).join("")} ${(r.services||[]).filter(s=>s.product).map(s=>`<span class="tag">${esc(String(s.port))}/${esc(s.product)}</span>`).join("")}</td>`},
  ];
  renderTable("ips", cols, rows, all.length);
}
function renderAsns(){
  const all=scanData.asn_assets||[];
  if(!all.length){ $("showing").textContent=""; $("panel").innerHTML=`<p class="muted">No ASN data yet.</p>`; return; }
  let rows=all.slice(); const f=filterText();
  if(f) rows=rows.filter(r=>("as"+r.asn).includes(f)||(r.org||"").toLowerCase().includes(f)||(r.prefixes||[]).join(",").includes(f));
  const cols=[
    {key:"asn",label:"ASN",val:r=>parseInt(r.asn)||0,cell:r=>`<td class="mono">AS${esc(r.asn)}</td>`},
    {key:"org",label:"Organization",val:r=>r.org||"",cell:r=>`<td>${esc(r.org)}</td>`},
    {key:"prefixes",label:"Netblocks",val:r=>(r.prefixes||[]).length,cell:r=>`<td class="mono muted">${(r.prefixes||[]).map(esc).join("<br>")}</td>`},
    {key:"ip_count",label:"IPs seen",val:r=>r.ip_count||0,cell:r=>`<td>${r.ip_count}</td>`},
  ];
  renderTable("asns", cols, rows, all.length);
}
function renderEndpoints(){
  const all=scanData.endpoints||[];
  if(!all.length){ $("showing").textContent=""; $("panel").innerHTML=`<p class="muted">No endpoints. Tick <b>crawl</b> or click <b>⛏ Crawl</b> on a loaded scan (needs katana/gau).</p>`; return; }
  let rows=all.slice(); if($("onlyParams").checked) rows=rows.filter(r=>r.params);
  if(facet.epStatus.size) rows=rows.filter(r=>facet.epStatus.has(epBucket(r.status)));
  const f=filterText(); if(f) rows=rows.filter(r=>r.url.toLowerCase().includes(f)||(r.host||"").includes(f)||(r.ext||"").includes(f));
  const cols=[
    {key:"status",label:"Status",val:r=>r.status||0,cell:r=>`<td>${r.status?`<span class="st ${statusClass(r.status)}">${r.status}</span>`:'<span class="muted" title="not probed">?</span>'}</td>`},
    {key:"url",label:"URL",val:r=>r.url||"",cell:r=>`<td class="mono"><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.url.length>110?r.url.slice(0,110)+'…':r.url)}</a></td>`},
    {key:"host",label:"Host",val:r=>r.host||"",cell:r=>`<td class="mono muted">${esc(r.host)}</td>`},
    {key:"params",label:"Params",val:r=>r.params?1:0,cell:r=>`<td>${r.params?'<span class="yes">✓</span>':'<span class="no">–</span>'}</td>`},
    {key:"ext",label:"Ext",val:r=>r.ext||"",cell:r=>`<td class="mono muted">${esc(r.ext)}</td>`},
    {key:"source",label:"Source",val:r=>r.source||"",cell:r=>`<td><span class="tag">${esc(r.source)}</span></td>`},
    {key:"act",label:"",nosort:true,cell:r=>`<td style="white-space:nowrap"><button class="ghost sm" title="Fuzz this URL" onclick="pivotFuzz('${esc(r.url)}')">🎯</button> <button class="ghost sm" title="Nuclei this URL" onclick="pivotNuclei('${esc(r.url)}')">☢</button></td>`},
  ];
  renderTable("endpoints", cols, rows, all.length, 1500);
}
function renderTakeovers(){
  const all=scanData.takeovers||[];
  if(!all.length){ $("showing").textContent=""; $("panel").innerHTML=`<p class="muted">No subdomain-takeover candidates found — a dangling CNAME pointing at an unclaimed service would appear here.</p>`; return; }
  let rows=all.slice(); const f=filterText();
  if(f) rows=rows.filter(r=>r.host.includes(f)||(r.cname||"").includes(f)||(r.service||"").toLowerCase().includes(f));
  const cols=[
    {key:"confidence",label:"Confidence",val:r=>r.confidence==="high"?0:1,cell:r=>`<td><span class="tobadge ${r.confidence}">${esc(r.confidence)}</span></td>`},
    {key:"host",label:"Host",val:r=>r.host,cell:r=>`<td class="mono">${esc(r.host)}</td>`},
    {key:"service",label:"Service",val:r=>r.service,cell:r=>`<td>${esc(r.service)}</td>`},
    {key:"cname",label:"CNAME target",val:r=>r.cname,cell:r=>`<td class="mono muted">${esc(r.cname)}</td>`},
    {key:"evidence",label:"Evidence",nosort:true,cell:r=>`<td class="muted">${esc(r.evidence||"")}</td>`},
  ];
  renderTable("takeovers", cols, rows, all.length);
}
function renderRelated(){
  const all=scanData.related_domains||[];
  if(!all.length){ $("showing").textContent=""; $("panel").innerHTML=`<p class="muted">No related domains found. Add a Whoxy key for reverse-WHOIS expansion.</p>`; return; }
  let rows=all.map(d=>({domain:d})); const f=filterText(); if(f) rows=rows.filter(r=>r.domain.includes(f));
  const cols=[
    {key:"domain",label:"Related domain",val:r=>r.domain,cell:r=>`<td class="mono">${esc(r.domain)}</td>`},
    {key:"_act",label:"",nosort:true,cell:r=>`<td><button class="ghost sm" onclick="document.getElementById('domain').value='${esc(r.domain)}';window.scrollTo(0,0);">scan this</button></td>`},
  ];
  renderTable("related", cols, rows, all.length);
}
const SEV_RANK = {critical:0,high:1,medium:2,low:3,info:4,unknown:5};
function findingRows(){
  const f=(scanData&&scanData.findings)||{}; const rows=[];
  (f.nuclei||[]).forEach(n=>rows.push({_t:"nuclei",severity:(n.severity||"unknown"),label:n.template||"",name:n.name||"",url:n.url||"",tags:n.tags||[],extra:n.matcher||""}));
  (f.exposures||[]).forEach(e=>rows.push({_t:"exposure",severity:(e.severity||"info"),label:e.type||"",name:e.type||"",url:e.url||"",tags:[],extra:e.evidence||""}));
  (f.fuzz||[]).forEach(x=>rows.push({_t:"fuzz",severity:"info",label:(x.status!=null?String(x.status):""),name:x.path||x.url||"",url:x.url||"",tags:[],extra:(x.size!=null?fzHuman(x.size):"")+(x.source?(" · "+x.source):"")}));
  (f.params||[]).forEach(x=>rows.push({_t:"param",severity:"info",label:x.method||"GET",name:"params: "+((x.params||[]).join(", ")),url:x.url||"",tags:x.params||[],extra:x.source||"arjun"}));
  (f.vhost||[]).forEach(x=>rows.push({_t:"vhost",severity:"info",label:String(x.status||""),name:x.vhost||"",url:"",tags:[],extra:`on ${x.host||"?"}${x.size!=null?" · "+fzHuman(x.size):""}`}));
  return rows;
}
function renderFindings(){
  const all=findingRows();
  if(!all.length){ $("showing").textContent=""; $("panel").innerHTML=`<p class="muted">No saved findings yet. Run the <b>☢ Nuclei</b> or <b>🎯 Fuzzer</b> tab <b>with a scan loaded</b> (run/import/History) — their results get saved here, into the scan, and into reports. Nuclei findings and exposed-file hits are the high-signal ones.</p>`; return; }
  let rows=all.slice();
  if(facet.findType.size) rows=rows.filter(r=>facet.findType.has(r._t));
  const ff=filterText(); if(ff) rows=rows.filter(r=>(r.url||"").toLowerCase().includes(ff)||(r.name||"").toLowerCase().includes(ff)||(r.label||"").toLowerCase().includes(ff)||(r.tags||[]).join(",").toLowerCase().includes(ff)||r._t.includes(ff));
  const cols=[
    {key:"severity",label:"Severity",val:r=>SEV_RANK[r.severity]!=null?SEV_RANK[r.severity]:9,cell:r=>`<td><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></td>`},
    {key:"_t",label:"Type",val:r=>r._t,cell:r=>`<td><span class="tag">${esc(r._t)}</span></td>`},
    {key:"label",label:"Template / Path",val:r=>r.label||"",cell:r=>`<td class="mono">${esc(r.label)}</td>`},
    {key:"name",label:"Name",val:r=>r.name||"",cell:r=>`<td>${esc(r.name)}</td>`},
    {key:"url",label:"Matched URL",val:r=>r.url||"",cell:r=>`<td class="mono"><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc((r.url||"").length>90?r.url.slice(0,90)+'…':r.url)}</a></td>`},
    {key:"extra",label:"Detail",nosort:true,cell:r=>`<td class="muted">${(r.tags||[]).slice(0,4).map(t=>`<span class="tag">${esc(t)}</span>`).join("")}${esc(r.extra)}</td>`},
    {key:"act",label:"",nosort:true,cell:r=>{const snip=encodeURIComponent(reportSnippet(r));return `<td style="white-space:nowrap">${r.url?`<button class="ghost sm" title="Nuclei this URL" onclick="pivotNuclei('${esc(r.url)}')">☢</button> `:""}<button class="ghost sm" title="Copy as a report line" onclick="copyFinding('${snip}',this)">📋</button></td>`;}},
  ];
  renderTable("findings", cols, rows, all.length, 2000);
}

// ---------- LLM ----------
function thinkingMsg(){ return $("useLocal").checked?"Thinking (local model)…":"Thinking…"; }
async function explain(){
  if(!currentScanId){ $("llmOut").textContent="Run or load a scan first."; return; }
  $("llmOut").textContent=thinkingMsg();
  const r=await (await fetch("/api/llm/explain",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scan_id:currentScanId, prefer_local:$("useLocal").checked})})).json();
  $("llmOut").textContent=r.text;
}
async function ask(){
  const q=$("ask").value.trim(); if(!q) return;
  $("llmOut").textContent=thinkingMsg();
  const r=await (await fetch("/api/llm/ask",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question:q, scan_id:currentScanId, prefer_local:$("useLocal").checked})})).json();
  $("llmOut").textContent=r.text; $("ask").value="";
}

// ---------- exports ----------
function dl(name, text, type){ const b=new Blob([text],{type:type||"text/plain"}); const a=document.createElement("a"); a.href=URL.createObjectURL(b); a.download=name; a.click(); }
async function doExport(kind){
  if(!scanData) return;
  const d=scanData.domain;
  $("exportMenu").classList.remove("show");
  if(kind==="md"||kind==="html"){
    if(!currentScanId){ alert("Run or load a scan first."); return; }
    try{
      const res=await fetch(`/api/scan/${currentScanId}/report?fmt=${kind}`);
      if(!res.ok){ alert("Report generation failed."); return; }
      const text=await res.text();
      dl(`${d}_recon.${kind==="html"?"html":"md"}`, text, kind==="html"?"text/html":"text/markdown");
    }catch(e){ alert("Report generation failed."); }
    return;
  }
  if(kind==="json") dl(`${d}_recon.json`, JSON.stringify(scanData,null,2), "application/json");
  else if(kind==="csv"){
    const rows=[["host","live","status","title","server","tech","ips","takeover","sources"]];
    (scanData.hosts||[]).forEach(h=>rows.push([h.host,h.live?1:0,h.status||"",(h.title||"").replace(/"/g,"'"),h.server||"",(h.tech||[]).join("|"),(h.ips||[]).join("|"),h.takeover?h.takeover.service:"",(h.sources||[]).join("|")]));
    dl(`${d}_subdomains.csv`, rows.map(r=>r.map(c=>`"${String(c)}"`).join(",")).join("\n"), "text/csv");
  }
  else if(kind==="live") dl(`${d}_live.txt`, (scanData.hosts||[]).filter(h=>h.live&&h.url).map(h=>h.url).join("\n"));
  else if(kind==="nuclei") dl(`${d}_targets.txt`, (scanData.hosts||[]).filter(h=>h.live&&h.url).map(h=>h.url).join("\n"));
  $("exportMenu").classList.remove("show");
}

// ---------- standalone crawl ----------
function selectTab(name){ activeTab=name; document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active",t.dataset.tab===name)); render(); }
function resetCrawlBtn(){ $("crawlBtn").disabled=false; $("crawlBtn").textContent="⛏ Crawl"; }
async function runCrawl(){
  if(!currentScanId||!scanData){ alert("Run, load, or import a scan first."); return; }
  if(!(scanData.counts||{}).live){ alert("This scan has no live hosts to crawl."); return; }
  $("crawlBtn").disabled=true; $("crawlBtn").textContent="Crawling…"; $("phase").textContent="▸ starting crawl…";
  const r=await (await fetch("/api/crawl",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scan_id:currentScanId, deep:$("deep").checked})})).json();
  if(!r.job_id){ alert(r.detail||"Crawl failed to start"); resetCrawlBtn(); return; }
  const es=new EventSource(`/api/crawl/${r.job_id}/events`);
  es.onmessage=(e)=>{ const ev=JSON.parse(e.data);
    if(ev.kind==="phase") $("phase").textContent="▸ "+ev.phase;
    if(ev.kind==="endpoints") $("cEndpoints").textContent=ev.count;
    if(ev.kind==="done"||ev.kind==="error"){ es.close(); resetCrawlBtn();
      $("phase").textContent=ev.kind==="error"?"⚠ "+(ev.message||"crawl error"):"✓ crawl complete";
      refresh(currentScanId).then(()=>selectTab("endpoints")); } };
  es.onerror=()=>{ es.close(); resetCrawlBtn(); refresh(currentScanId); };
}

// ---------- scan diff (compare with a previous scan) ----------
let lastDiff = null;  // {prior, sets} for markdown export
function scanSets(s){
  const hosts = s.hosts||[];
  const ips=new Set(), ports=new Set();
  (s.ip_assets||[]).forEach(r=>{ ips.add(r.ip); (r.ports||[]).forEach(p=>ports.add(r.ip+":"+p)); });
  hosts.forEach(h=>(h.ips||[]).forEach(ip=>ips.add(ip)));
  return {
    subdomains:new Set(hosts.map(h=>h.host)),
    live:new Set(hosts.filter(h=>h.live).map(h=>h.host)),
    ips, ports,
    endpoints:new Set((s.endpoints||[]).map(e=>e.url)),
    related:new Set(s.related_domains||[]),
  };
}
function diffLists(cur, prior){ return { add:[...cur].filter(x=>!prior.has(x)).sort(), rem:[...prior].filter(x=>!cur.has(x)).sort() }; }
async function openDiff(){
  if(!scanData){ alert("Run, load, or import a scan first."); return; }
  const list=((await (await fetch("/api/scans")).json()).scans||[])
    .filter(s=>s.domain===scanData.domain && s.finished && s.finished!==scanData.finished);
  const sel=$("diffSelect");
  if(!list.length){
    sel.innerHTML=`<option value="">— no earlier scans of ${esc(scanData.domain)} —</option>`;
    $("diffResult").innerHTML=`<p class="muted">Run this target again later, then come back to see what changed.</p>`;
  }else{
    sel.innerHTML=`<option value="">Choose a scan to compare against…</option>`+list.map(s=>{
      const c=s.counts||{}, when=s.finished?new Date(s.finished*1000).toLocaleString():s.file;
      return `<option value="${esc(s.file)}">${esc(when)} · ${c.total||0} subs · ${c.live||0} live</option>`;
    }).join("");
    $("diffResult").innerHTML="";
  }
  $("diffOverlay").classList.add("show");
}
async function runDiff(file){
  if(!file){ $("diffResult").innerHTML=""; lastDiff=null; return; }
  $("diffResult").innerHTML=`<p class="muted">Comparing…</p>`;
  let prior; try{ prior=await (await fetch(`/api/scans/${encodeURIComponent(file)}`)).json(); }
  catch(e){ $("diffResult").innerHTML=`<p class="muted">Could not load that scan.</p>`; return; }
  const cur=scanSets(scanData), old=scanSets(prior);
  const cats=[
    ["Subdomains","subdomains"],["Live hosts","live"],["IPs","ips"],
    ["Open ports","ports"],["Endpoints","endpoints"],["Related domains","related"],
  ];
  const diffs={}; cats.forEach(([,k])=>diffs[k]=diffLists(cur[k], old[k]));
  lastDiff={prior, diffs, cats};
  const chips=cats.map(([label,k])=>{
    const a=diffs[k].add.length, r=diffs[k].rem.length;
    return `<span class="chip">${esc(label)} <b>+${a}</b></span>`+(r?`<span class="chip r"><b>−${r}</b></span>`:"");
  }).join("");
  const box=(cls,title,items)=>`<div class="diffbox ${cls}"><h4>${title} (${items.length})</h4>`+
    (items.length?`<ul>${items.slice(0,300).map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`
      :`<p class="muted" style="margin:0">none</p>`)+`</div>`;
  const sections=cats.filter(([,k])=>diffs[k].add.length||diffs[k].rem.length).map(([label,k])=>
    `<h3 style="margin:14px 0 6px;color:var(--text)">${esc(label)}</h3>
     <div class="diffgrid">${box("add","🆕 New",diffs[k].add)}${box("rem","➖ Gone",diffs[k].rem)}</div>`).join("");
  $("diffResult").innerHTML=`<div class="diffsum">${chips}</div>`+
    (sections||`<p class="muted">No differences — the two scans found the same assets.</p>`);
}
function exportDiff(){
  if(!lastDiff){ alert("Pick a scan to compare against first."); return; }
  const {prior,diffs,cats}=lastDiff;
  const when=s=>s?new Date((s.finished||0)*1000).toLocaleString():"?";
  let md=`# ReconMind diff — ${scanData.domain}\n\n`;
  md+=`Comparing **current** (${when(scanData)}) against **previous** (${when(prior)}).\n\n`;
  cats.forEach(([label,k])=>{
    const {add,rem}=diffs[k]; if(!add.length&&!rem.length) return;
    md+=`## ${label} (+${add.length} / −${rem.length})\n\n`;
    add.forEach(x=>md+=`- 🆕 ${x}\n`);
    rem.forEach(x=>md+=`- ➖ ${x}\n`);
    md+=`\n`;
  });
  dl(`${scanData.domain}_diff.md`, md, "text/markdown");
}

// ========================================================================
// Fuzzer tab — Postman-style manual content discovery
// ========================================================================
let FUZZ = {
  method:"GET", url:"", tool:"", wordlist:"", wordlist2:"", extensions:"", match_codes:"",
  filter_codes:"404", threads:40, rps:0, recursion:0, quick_wins:false, data:"",
  headers:[{name:"",value:""}], rows:[], exposures:[], running:false,
  jobId:null, es:null, filter:"", statusFacet:new Set(),
  regex:false, hideSize:null, minWords:null, exclude:"",
};
function refocusEl(id){ const n=$(id); if(n){ n.focus(); try{ n.setSelectionRange(n.value.length,n.value.length); }catch(e){} } }
// Comma-separated negative filter: returns rows that DON'T contain any term.
function applyExclude(rows, ex, fields){
  const terms=(ex||"").split(",").map(s=>s.trim().toLowerCase()).filter(Boolean);
  if(!terms.length) return rows;
  return rows.filter(r=>{ const blob=fields.map(f=>String(r[f]||"")).join(" ").toLowerCase(); return !terms.some(t=>blob.includes(t)); });
}
let FUZZ_META = { wordlists:null, tools:null };
const FZ_INTERESTING = /(admin|backup|\.bak|\.old|\.sql|\.zip|\.tar|\.git|\.env|config|secret|token|api|graphql|upload|debug|test|internal|private|swagger|actuator|\.json|\.xml|password|\.log)/i;

function fzHuman(n){ if(n==null) return ""; if(n<1024) return n+"B"; if(n<1048576) return (n/1024).toFixed(1)+"KB"; return (n/1048576).toFixed(1)+"MB"; }

async function loadFuzzMeta(){
  try{
    if(!FUZZ_META.tools){ FUZZ_META.tools = (await (await fetch("/api/fuzz/tools")).json()); if(!FUZZ.tool) FUZZ.tool = FUZZ_META.tools.default||"ffuf"; }
    if(!FUZZ_META.wordlists){ FUZZ_META.wordlists = (await (await fetch("/api/wordlists")).json()).wordlists||[]; }
  }catch(e){ FUZZ_META.tools=FUZZ_META.tools||{tools:[]}; FUZZ_META.wordlists=FUZZ_META.wordlists||[]; }
  populateFuzzSelects();
}
function populateFuzzSelects(){
  const tsel=$("fzTool"); if(tsel && FUZZ_META.tools){
    tsel.innerHTML=(FUZZ_META.tools.tools||[]).map(t=>`<option value="${esc(t.name)}" ${t.available?"":"disabled"}>${esc(t.name)}${t.available?"":" — not installed"}</option>`).join("");
    if(FUZZ.tool) tsel.value=FUZZ.tool; if(tsel.selectedIndex<0||tsel.value!==FUZZ.tool){ const first=(FUZZ_META.tools.tools||[]).find(t=>t.available); if(first){ tsel.value=first.name; FUZZ.tool=first.name; } }
  }
  if(FUZZ_META.wordlists){
    const groups={}; FUZZ_META.wordlists.forEach(w=>{ (groups[w.group]=groups[w.group]||[]).push(w); });
    const opts=Object.entries(groups).map(([g,ws])=>`<optgroup label="${esc(g)}">`+ws.map(w=>`<option value="${esc(w.path)}">${esc(w.name)} · ${w.lines>=0?w.lines.toLocaleString()+" lines":w.human}</option>`).join("")+`</optgroup>`).join("");
    const wsel=$("fzWordlist"); if(wsel){ wsel.innerHTML=`<option value="">— choose a wordlist —</option>`+opts; if(FUZZ.wordlist) wsel.value=FUZZ.wordlist; }
    const w2=$("fzWordlist2"); if(w2){ w2.innerHTML=`<option value="">— none —</option>`+opts; if(FUZZ.wordlist2) w2.value=FUZZ.wordlist2; }
  }
  updateToolHints();
}
function toolMeta(name){ return ((FUZZ_META.tools||{}).tools||[]).find(t=>t.name===name)||{}; }
function updateToolHints(){
  const m=toolMeta(FUZZ.tool); const h=$("fzToolHint"); if(h) h.textContent=m.purpose||"";
  const rec=$("fzRecursion"); if(rec){ rec.disabled=!m.supports_recursion; rec.title=m.supports_recursion?"recursion depth (0 = off)":`${FUZZ.tool} doesn't support recursion`; }
}

function fuzzFormHTML(){
  const liveHosts=(scanData&&scanData.hosts?scanData.hosts.filter(h=>h.live&&h.url):[]);
  const fromScan = liveHosts.length ? `<label class="fl" style="max-width:260px">from scan
      <select id="fzFromScan"><option value="">— live hosts (${liveHosts.length}) —</option>${liveHosts.map(h=>`<option value="${esc(h.url)}">${esc(h.host)}</option>`).join("")}</select></label>` : "";
  return `<div class="fz" id="fzForm">
    <div class="row" style="gap:6px;align-items:center">
      <span class="small">profile</span>
      <select id="fzProfileSel" class="modelsel"></select>
      <button class="iconbtn" id="fzProfLoad">Load</button>
      <button class="iconbtn" id="fzProfSave">Save…</button>
      <button class="iconbtn rm" id="fzProfDel">✕</button>
    </div>
    <div class="row">
      <label class="fl">method
        <select id="fzMethod" class="method">${["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"].map(m=>`<option ${FUZZ.method===m?"selected":""}>${m}</option>`).join("")}</select></label>
      <label class="fl" style="flex:1">target URL <span class="small">(mark the inject point with <code>FUZZ</code> — auto-appended if omitted)</span>
        <input type="text" id="fzUrl" placeholder="https://target.com/FUZZ" value="${esc(FUZZ.url)}"></label>
      ${fromScan}
      <button id="fzStart" class="warn" style="align-self:flex-end">▶ Start</button>
      <button id="fzStop" class="ghost" style="align-self:flex-end" ${FUZZ.running?"":"disabled"}>■ Stop</button>
    </div>
    <div class="row" style="align-items:flex-end">
      <label class="fl" style="flex:1;min-width:200px">wordlist <span class="small">(FUZZ)</span>
        <select id="fzWordlist"></select></label>
      <label class="fl" style="flex:1;min-width:160px">2nd wordlist <span class="small">(FUZ2 — optional, multi-fuzz, ffuf)</span>
        <select id="fzWordlist2"></select></label>
      <label class="fl" style="max-width:160px">tool
        <select id="fzTool"></select></label>
      <span class="small" id="fzToolHint" style="max-width:200px"></span>
    </div>
    <div class="grp">
      <h4>Headers <span class="small">(sent with every request)</span></h4>
      <div id="fzHeaders"></div>
      <button class="iconbtn" id="fzAddHeader" style="margin-top:8px">＋ Add header</button>
    </div>
    <div id="fzBodyWrap" class="grp" ${["POST","PUT","PATCH","DELETE"].includes(FUZZ.method)?"":'hidden'}>
      <h4>Request body</h4>
      <textarea id="fzData" placeholder='e.g. {"q":"FUZZ"} or a=1&b=FUZZ'>${esc(FUZZ.data)}</textarea>
    </div>
    <div class="opts">
      <label class="fl">extensions<input type="text" class="wide" id="fzExt" placeholder="php,txt,bak" value="${esc(FUZZ.extensions)}"></label>
      <label class="fl">match codes<input type="text" id="fzMatch" placeholder="all" value="${esc(FUZZ.match_codes)}" title="status codes to keep (ffuf -mc). blank = all"></label>
      <label class="fl">filter codes<input type="text" id="fzFilter" placeholder="404" value="${esc(FUZZ.filter_codes)}" title="status codes to drop (ffuf -fc)"></label>
      <label class="fl">threads<input type="text" id="fzThreads" value="${esc(String(FUZZ.threads))}"></label>
      <label class="fl">rate/s<input type="text" id="fzRps" value="${esc(String(FUZZ.rps))}" title="requests/sec, 0 = unlimited"></label>
      <label class="fl">recursion<input type="text" id="fzRecursion" value="${esc(String(FUZZ.recursion))}" title="recursion depth (0 = off)"></label>
      <label class="chk" style="align-self:flex-end" title="also probe .git/.env/swagger/actuator/backups on this host (validated, no false positives)"><input type="checkbox" id="fzQuick" ${FUZZ.quick_wins?"checked":""}> quick-win files</label>
    </div>
    <div class="phase" id="fzPhase"></div>
  </div>
  <div id="fzOut"></div>`;
}
function renderHeaderRows(){
  const c=$("fzHeaders"); if(!c) return;
  if(!FUZZ.headers.length) FUZZ.headers=[{name:"",value:""}];
  c.innerHTML=FUZZ.headers.map((h,i)=>`<div class="hdr" style="margin:6px 0">
    <input type="text" class="hk" data-hi="${i}" data-hf="name" placeholder="Header-Name" value="${esc(h.name)}">
    <input type="text" data-hi="${i}" data-hf="value" placeholder="value" value="${esc(h.value)}">
    <button class="iconbtn rm" data-hrm="${i}" title="remove">✕</button></div>`).join("");
  c.querySelectorAll("[data-hrm]").forEach(b=>b.onclick=()=>{ readHeaderRows(); FUZZ.headers.splice(+b.dataset.hrm,1); renderHeaderRows(); });
}
function readHeaderRows(){
  const rows=[]; document.querySelectorAll("#fzHeaders .hdr").forEach(r=>{
    const n=r.querySelector('[data-hf="name"]').value, v=r.querySelector('[data-hf="value"]').value; rows.push({name:n,value:v}); });
  if(rows.length) FUZZ.headers=rows; return FUZZ.headers;
}
function syncFuzzState(){
  const g=(id)=>$(id)?$(id).value:"";
  FUZZ.method=g("fzMethod")||"GET"; FUZZ.url=g("fzUrl"); FUZZ.tool=g("fzTool")||FUZZ.tool;
  FUZZ.wordlist=g("fzWordlist"); FUZZ.wordlist2=g("fzWordlist2"); FUZZ.extensions=g("fzExt"); FUZZ.match_codes=g("fzMatch");
  FUZZ.filter_codes=g("fzFilter"); FUZZ.threads=parseInt(g("fzThreads"))||40; FUZZ.rps=parseInt(g("fzRps"))||0;
  FUZZ.recursion=parseInt(g("fzRecursion"))||0; FUZZ.data=g("fzData"); FUZZ.quick_wins=$("fzQuick")?$("fzQuick").checked:false;
  readHeaderRows();
}
// ---------- saved profiles (shared by Fuzzer + Nuclei) ----------
let PROFILES = { fuzz:{}, nuclei:{} };
async function loadProfiles(){ try{ PROFILES=await (await fetch("/api/profiles")).json(); }catch(e){ PROFILES={fuzz:{},nuclei:{}}; } }
function fillProfileSel(id, kind){ const s=$(id); if(!s) return; const names=Object.keys(PROFILES[kind]||{}).sort(); s.innerHTML=`<option value="">— profiles (${names.length}) —</option>`+names.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join(""); }
async function saveProfilePrompt(kind, cfg, selId){
  const name=prompt("Save profile as:"); if(!name||!name.trim()) return;
  const r=await fetch("/api/profiles",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({kind,name:name.trim(),config:cfg})});
  if(!r.ok){ const d=await r.json().catch(()=>({})); alert(d.detail||"save failed"); return; }
  await loadProfiles(); fillProfileSel(selId,kind); const s=$(selId); if(s) s.value=name.trim();
}
async function deleteProfileSel(kind, selId){ const n=$(selId)&&$(selId).value; if(!n) return; if(!confirm(`Delete profile "${n}"?`)) return; await fetch(`/api/profiles/${kind}/${encodeURIComponent(n)}`,{method:"DELETE"}); await loadProfiles(); fillProfileSel(selId,kind); }

function fuzzConfig(){ syncFuzzState(); return {method:FUZZ.method,tool:FUZZ.tool,wordlist:FUZZ.wordlist,wordlist2:FUZZ.wordlist2,extensions:FUZZ.extensions,match_codes:FUZZ.match_codes,filter_codes:FUZZ.filter_codes,threads:FUZZ.threads,rps:FUZZ.rps,recursion:FUZZ.recursion,quick_wins:FUZZ.quick_wins,headers:FUZZ.headers}; }
function applyFuzzConfig(cfg){ Object.assign(FUZZ,{method:cfg.method||"GET",tool:cfg.tool||FUZZ.tool,wordlist:cfg.wordlist||"",wordlist2:cfg.wordlist2||"",extensions:cfg.extensions||"",match_codes:cfg.match_codes||"",filter_codes:cfg.filter_codes!=null?cfg.filter_codes:"404",threads:cfg.threads||40,rps:cfg.rps||0,recursion:cfg.recursion||0,quick_wins:!!cfg.quick_wins,headers:(cfg.headers&&cfg.headers.length)?cfg.headers:[{name:"",value:""}]}); buildFuzzForm(); }

function buildFuzzForm(){
  $("panel").innerHTML=fuzzFormHTML();
  renderHeaderRows();
  $("fzAddHeader").onclick=()=>{ readHeaderRows(); FUZZ.headers.push({name:"",value:""}); renderHeaderRows(); };
  $("fzStart").onclick=startFuzz; $("fzStop").onclick=stopFuzz;
  $("fzMethod").onchange=()=>{ FUZZ.method=$("fzMethod").value; $("fzBodyWrap").hidden=!["POST","PUT","PATCH","DELETE"].includes(FUZZ.method); };
  $("fzTool").onchange=()=>{ FUZZ.tool=$("fzTool").value; updateToolHints(); };
  const fs=$("fzFromScan"); if(fs) fs.onchange=()=>{ if(fs.value){ $("fzUrl").value=fs.value; FUZZ.url=fs.value; } };
  $("fzProfLoad").onclick=()=>{ const n=$("fzProfileSel").value; if(n&&PROFILES.fuzz[n]) applyFuzzConfig(PROFILES.fuzz[n]); };
  $("fzProfSave").onclick=()=>saveProfilePrompt("fuzz", fuzzConfig(), "fzProfileSel");
  $("fzProfDel").onclick=()=>deleteProfileSel("fuzz","fzProfileSel");
  loadProfiles().then(()=>fillProfileSel("fzProfileSel","fuzz"));
  loadFuzzMeta();
}
function renderFuzzer(){
  if(!$("fzForm")) buildFuzzForm();
  renderFuzzResults();
}
let fzRenderPending=false;
function scheduleFuzzRender(){ if(fzRenderPending) return; fzRenderPending=true; setTimeout(()=>{ fzRenderPending=false; if(activeTab==="fuzzer") renderFuzzResults(); },350); }

function startFuzz(){
  syncFuzzState();
  if(!FUZZ.url.trim()){ alert("Enter a URL to fuzz, e.g. https://target.com/FUZZ"); return; }
  if(!FUZZ.wordlist){ alert("Pick a wordlist from the dropdown."); return; }
  const m=toolMeta(FUZZ.tool); if(m && m.available===false){ alert(FUZZ.tool+" is not installed."); return; }
  FUZZ.rows=[]; FUZZ.exposures=[]; FUZZ.running=true;
  if(FUZZ.es){ try{FUZZ.es.close();}catch(e){} }
  updateFuzzButtons(); renderFuzzResults();
  const body={ url:FUZZ.url, tool:FUZZ.tool, wordlist:FUZZ.wordlist, wordlist2:FUZZ.wordlist2, method:FUZZ.method,
    headers:FUZZ.headers.filter(h=>h.name.trim()), extensions:FUZZ.extensions,
    match_codes:FUZZ.match_codes, filter_codes:FUZZ.filter_codes, threads:FUZZ.threads,
    rps:FUZZ.rps, recursion:FUZZ.recursion, data:FUZZ.data, quick_wins:FUZZ.quick_wins,
    scan_id:currentScanId };
  $("fzPhase").textContent="▸ starting…";
  fetch("/api/fuzz",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
    .then(r=>r.json()).then(res=>{
      if(!res.job_id){ $("fzPhase").textContent="⚠ "+(res.detail||"failed to start"); FUZZ.running=false; updateFuzzButtons(); return; }
      FUZZ.jobId=res.job_id;
      const es=new EventSource(`/api/fuzz/${res.job_id}/events`); FUZZ.es=es;
      es.onmessage=(e)=>{ const ev=JSON.parse(e.data);
        if(ev.kind==="phase") $("fzPhase").textContent="▸ "+ev.phase;
        else if(ev.kind==="result"){ FUZZ.rows.push(ev.row); scheduleFuzzRender(); }
        else if(ev.kind==="exposure"){ FUZZ.exposures.push(ev.row); scheduleFuzzRender(); }
        else if(ev.kind==="done"){ es.close(); FUZZ.running=false; updateFuzzButtons();
          $("fzPhase").textContent=`✓ done — ${FUZZ.rows.length} result${FUZZ.rows.length===1?"":"s"}${ev.exposures?`, ${ev.exposures} exposure${ev.exposures===1?"":"s"}`:""}${ev.truncated?" (capped at 5000)":""}${ev.saved?" · saved to Findings":""}`; renderFuzzResults(); if(ev.saved) refreshFindings(); }
        else if(ev.kind==="error"){ es.close(); FUZZ.running=false; updateFuzzButtons(); $("fzPhase").textContent="⚠ "+(ev.message||"error"); renderFuzzResults(); }
      };
      es.onerror=()=>{ es.close(); FUZZ.running=false; updateFuzzButtons(); if(!$("fzPhase").textContent.startsWith("✓")) $("fzPhase").textContent="▸ stream ended"; };
    }).catch(()=>{ $("fzPhase").textContent="⚠ failed to start"; FUZZ.running=false; updateFuzzButtons(); });
}
function stopFuzz(){ if(FUZZ.es){ try{FUZZ.es.close();}catch(e){} } FUZZ.running=false; updateFuzzButtons(); $("fzPhase").textContent="■ stopped listening (server finishes the run under its time budget)"; }
function updateFuzzButtons(){ const s=$("fzStart"),t=$("fzStop"); if(s){ s.disabled=FUZZ.running; s.textContent=FUZZ.running?"running…":"▶ Start"; } if(t) t.disabled=!FUZZ.running; }

function renderFuzzResults(){
  const out=$("fzOut"); if(!out) return;
  let html="";
  if(FUZZ.exposures.length){
    html+=`<div class="expbox"><h4>⚠ Exposed files (${FUZZ.exposures.length}) — validated, likely reportable</h4>`+
      FUZZ.exposures.map(e=>`<div class="exprow"><span class="sev ${esc(e.severity)}">${esc(e.severity)}</span>
        <a href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.path)}</a>
        <span class="st ${statusClass(e.status)}">${e.status}</span>
        <span>${esc(e.type)}</span><span class="ev">${esc(e.evidence||"")}</span></div>`).join("")+`</div>`;
  }
  const total=FUZZ.rows.length;
  let rows=FUZZ.rows.slice();
  if(FUZZ.statusFacet.size) rows=rows.filter(r=>FUZZ.statusFacet.has(statusBucket(r.status)));
  const f=(FUZZ.filter||"");
  if(f){ if(FUZZ.regex){ let re=null; try{ re=new RegExp(f,"i"); }catch(e){} if(re) rows=rows.filter(r=>re.test(r.url||"")||re.test(r.path||"")); }
         else { const lf=f.toLowerCase(); rows=rows.filter(r=>(r.url||"").toLowerCase().includes(lf)||(r.path||"").toLowerCase().includes(lf)); } }
  rows=applyExclude(rows, FUZZ.exclude, ["url","path"]);
  if(FUZZ.hideSize!=null) rows=rows.filter(r=>r.size!==FUZZ.hideSize);
  if(FUZZ.minWords!=null) rows=rows.filter(r=>(r.words||0)>=FUZZ.minWords);
  const buckets=["2xx","3xx","4xx","5xx"];
  const facetChips=buckets.map(b=>`<span class="facet ${FUZZ.statusFacet.has(b)?'on':''}" data-fzs="${b}">${b} <b>${FUZZ.rows.filter(r=>statusBucket(r.status)===b).length}</b></span>`).join("");
  html+=`<div class="filterbar" style="margin-top:4px">
      <input id="fzResFilter" type="text" placeholder="filter (keep)…" style="min-width:130px;flex:0 1 200px" value="${esc(FUZZ.filter||"")}">
      <label class="chk" title="treat the keep-filter as a regular expression"><input type="checkbox" id="fzRegex" ${FUZZ.regex?"checked":""}> regex</label>
      <input id="fzExclude" type="text" placeholder="exclude a,b,c…" style="min-width:130px;flex:0 1 200px" value="${esc(FUZZ.exclude||"")}" title="hide results containing ANY of these comma-separated terms">
      <input id="fzHideSize" type="text" placeholder="hide size" value="${FUZZ.hideSize!=null?FUZZ.hideSize:''}" style="width:88px" title="hide results whose byte size equals this (soft-404 killer)">
      <input id="fzMinWords" type="text" placeholder="min words" value="${FUZZ.minWords!=null?FUZZ.minWords:''}" style="width:88px" title="keep only results with at least this many words">
      <span class="muted">${rows.length} / ${total}${FUZZ.running?' · <span style="color:var(--warn)">live…</span>':''}</span>
      <div style="margin-left:auto"><button class="ghost sm" id="fzExport" ${total?"":"disabled"}>⬇ Export URLs</button></div>
    </div>
    <div class="facets">${facetChips}</div>`;
  if(!total){
    html+=`<p class="muted">${FUZZ.running?"Fuzzing… results will stream in here.":"No results yet. Pick a wordlist + tool above and hit <b>Start</b>. Tip: put <code>FUZZ</code> in the URL to control exactly where the wordlist is injected (e.g. <code>https://host/api/FUZZ</code> or <code>https://host/?id=FUZZ</code>)."}</p>`;
  } else {
    const sorted=rows.sort((a,b)=>(a.status||0)-(b.status||0)||(a.path||"").localeCompare(b.path||"")).slice(0,3000);
    html+=`<table><thead><tr><th>Status</th><th>Size</th><th>Words</th><th>Path / URL</th><th>Source</th></tr></thead><tbody>`+
      sorted.map(r=>{ const inter=FZ_INTERESTING.test(r.path||r.url);
        return `<tr><td><span class="st ${statusClass(r.status)}">${r.status==null?"?":r.status}</span></td>
        <td class="mono muted">${fzHuman(r.size)}</td><td class="mono muted">${r.words==null?"":r.words}</td>
        <td class="mono">${inter?'<span class="interesting" title="commonly interesting">★ </span>':''}<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc((r.path||r.url).length>110?(r.path||r.url).slice(0,110)+'…':(r.path||r.url))}</a>${r.redirect?` <span class="muted">→ ${esc(r.redirect.length>50?r.redirect.slice(0,50)+'…':r.redirect)}</span>`:''}</td>
        <td><span class="tag">${esc(r.source)}</span></td></tr>`; }).join("")+`</tbody></table>`;
    if(sorted.length<rows.length) html+=`<p class="muted">Showing first ${sorted.length} of ${rows.length} — refine the filter.</p>`;
  }
  out.innerHTML=html;
  const rf=$("fzResFilter"); if(rf) rf.oninput=()=>{ FUZZ.filter=rf.value; renderFuzzResults(); refocusEl("fzResFilter"); };
  const rg=$("fzRegex"); if(rg) rg.onchange=()=>{ FUZZ.regex=rg.checked; renderFuzzResults(); };
  const ex2=$("fzExclude"); if(ex2) ex2.oninput=()=>{ FUZZ.exclude=ex2.value; renderFuzzResults(); refocusEl("fzExclude"); };
  const hs=$("fzHideSize"); if(hs) hs.oninput=()=>{ const v=parseInt(hs.value); FUZZ.hideSize=isNaN(v)?null:v; renderFuzzResults(); refocusEl("fzHideSize"); };
  const mw=$("fzMinWords"); if(mw) mw.oninput=()=>{ const v=parseInt(mw.value); FUZZ.minWords=isNaN(v)?null:v; renderFuzzResults(); refocusEl("fzMinWords"); };
  out.querySelectorAll("[data-fzs]").forEach(el=>el.onclick=()=>{ const b=el.dataset.fzs; FUZZ.statusFacet.has(b)?FUZZ.statusFacet.delete(b):FUZZ.statusFacet.add(b); renderFuzzResults(); });
  const ex=$("fzExport"); if(ex) ex.onclick=()=>dl(`fuzz_${(scanData&&scanData.domain)||"results"}.txt`, FUZZ.rows.map(r=>r.url).join("\n"));
}

// ========================================================================
// Nuclei tab — UI-driven template vulnerability scanning
// ========================================================================
let NUKE = {
  targets:"", modules:[], tags:"", severity:new Set(["critical","high","medium"]),
  template_path:"", rate_limit:150, concurrency:25, bulk_size:25, timeout:10,
  retries:1, deadline:900, rows:[], running:false, es:null, filter:"", exclude:"", sevFacet:new Set(),
};
let NUKE_META = null;
const SEV_ORDER = ["critical","high","medium","low","info","unknown"];

async function loadNukeMeta(){
  if(!NUKE_META){ try{ NUKE_META = await (await fetch("/api/nuclei/meta")).json(); }catch(e){ NUKE_META={installed:false,modules:[],severities:SEV_ORDER,suggested_tags:[]}; } }
  const banner=$("nkBanner");
  if(banner){
    if(!NUKE_META.installed) banner.innerHTML=`<span style="color:var(--bad)">nuclei not installed</span> — <code>${esc(NUKE_META.install||"go install …/nuclei")}</code>`;
    else banner.innerHTML=`nuclei <b>${esc(NUKE_META.version||"")}</b> · ${(NUKE_META.modules||[]).length} module folders · templates: <code>${esc(NUKE_META.templates_dir||"?")}</code>`+(/^v[012](\.|$)/.test(NUKE_META.version||"")?` · <span style="color:var(--warn)">v3 available — <code>go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest</code></span>`:"");
  }
  const msel=$("nkModules");
  if(msel && NUKE_META.modules){ msel.innerHTML=NUKE_META.modules.map(m=>`<option value="${esc(m.path)}" ${NUKE.modules.includes(m.path)?"selected":""}>${esc(m.path)} (${m.count})</option>`).join(""); }
  const tagwrap=$("nkTagSuggest");
  if(tagwrap && NUKE_META.suggested_tags){ tagwrap.innerHTML=(NUKE_META.suggested_tags||[]).map(t=>`<span class="facet" data-nktag="${esc(t)}">${esc(t)}</span>`).join(""); tagwrap.querySelectorAll("[data-nktag]").forEach(el=>el.onclick=()=>{ const inp=$("nkTags"); const have=inp.value.split(/[\s,]+/).filter(Boolean); const t=el.dataset.nktag; if(!have.includes(t)) inp.value=(have.concat(t)).join(","); NUKE.tags=inp.value; }); }
}

function nukeFormHTML(){
  const liveHosts=(scanData&&scanData.hosts?scanData.hosts.filter(h=>h.live&&h.url):[]);
  const sevChip=(s)=>`<label class="chk" style="gap:5px"><input type="checkbox" class="nkSev" value="${s}" ${NUKE.severity.has(s)?"checked":""}> <span class="sev ${s}">${s}</span></label>`;
  return `<div class="fz" id="nkForm">
    <div class="nkbanner small" id="nkBanner"></div>
    <div class="row" style="gap:6px;align-items:center;margin-bottom:2px">
      <span class="small">profile</span>
      <select id="nkProfileSel" class="modelsel"></select>
      <button class="iconbtn" id="nkProfLoad">Load</button>
      <button class="iconbtn" id="nkProfSave">Save…</button>
      <button class="iconbtn rm" id="nkProfDel">✕</button>
    </div>
    <div class="grp">
      <h4>Targets <span class="small">— one per line; a single line uses -u, many use a temp -l file</span></h4>
      <textarea id="nkTargets" style="min-height:70px" placeholder="https://target.com&#10;https://api.target.com">${esc(NUKE.targets)}</textarea>
      <div class="row" style="margin-top:8px">
        ${liveHosts.length?`<button class="iconbtn" id="nkFromScan">＋ load ${liveHosts.length} live host(s) from scan</button>`:`<span class="small">load a scan to bulk-scan its live hosts</span>`}
        <button class="iconbtn" id="nkClearTargets">clear</button>
      </div>
    </div>
    <div class="grp">
      <h4>What to run <span class="small">— combine any of these; leave ALL blank = full scan (every template)</span></h4>
      <div class="row" style="align-items:flex-start;gap:16px">
        <label class="fl" style="min-width:220px">module folders <span class="small">(Cmd/Ctrl-click for several)</span>
          <input type="text" id="nkModSearch" placeholder="search modules… (e.g. cve, exposure)" style="margin-bottom:4px">
          <select id="nkModules" multiple size="8" style="min-width:240px"></select></label>
        <div style="flex:1;min-width:220px">
          <label class="fl">tags <span class="small">(comma separated)</span>
            <input type="text" id="nkTags" placeholder="cve,exposure,takeover" value="${esc(NUKE.tags)}"></label>
          <div class="facets" id="nkTagSuggest" style="margin-top:6px"></div>
          <label class="fl" style="margin-top:8px">custom template path <span class="small">(a .yaml or a dir)</span>
            <input type="text" id="nkTemplatePath" placeholder="/path/to/template.yaml" value="${esc(NUKE.template_path)}"></label>
        </div>
      </div>
      <div style="margin-top:10px">
        <div class="small" style="margin-bottom:4px">severity</div>
        <div class="row">${SEV_ORDER.map(sevChip).join("")}</div>
      </div>
    </div>
    <div class="opts">
      <label class="fl">rate limit/s<input type="text" id="nkRate" value="${esc(String(NUKE.rate_limit))}" title="-rl requests/sec"></label>
      <label class="fl">concurrency<input type="text" id="nkConc" value="${esc(String(NUKE.concurrency))}" title="-c templates in parallel"></label>
      <label class="fl">bulk size<input type="text" id="nkBulk" value="${esc(String(NUKE.bulk_size))}" title="-bs hosts per template"></label>
      <label class="fl">timeout<input type="text" id="nkTimeout" value="${esc(String(NUKE.timeout))}"></label>
      <label class="fl">retries<input type="text" id="nkRetries" value="${esc(String(NUKE.retries))}"></label>
      <label class="fl">max time (s)<input type="text" id="nkDeadline" value="${esc(String(NUKE.deadline))}" title="hard cap on the whole scan"></label>
      <div style="display:flex;gap:8px;align-self:flex-end">
        <button id="nkStart" class="warn" style="background:var(--bad);color:#fff">▶ Scan</button>
        <button id="nkStop" class="ghost" ${NUKE.running?"":"disabled"}>■ Stop</button>
      </div>
    </div>
    <div class="phase" id="nkPhase"></div>
  </div>
  <div id="nkOut"></div>`;
}
function syncNukeState(){
  const g=(id)=>$(id)?$(id).value:"";
  NUKE.targets=g("nkTargets"); NUKE.tags=g("nkTags"); NUKE.template_path=g("nkTemplatePath");
  NUKE.modules=$("nkModules")?Array.from($("nkModules").selectedOptions).map(o=>o.value):NUKE.modules;
  NUKE.severity=new Set(Array.from(document.querySelectorAll(".nkSev:checked")).map(c=>c.value));
  NUKE.rate_limit=parseInt(g("nkRate"))||150; NUKE.concurrency=parseInt(g("nkConc"))||25;
  NUKE.bulk_size=parseInt(g("nkBulk"))||25; NUKE.timeout=parseInt(g("nkTimeout"))||10;
  NUKE.retries=parseInt(g("nkRetries"))||1; NUKE.deadline=parseInt(g("nkDeadline"))||900;
}
function nukeConfig(){ syncNukeState(); return {modules:NUKE.modules,tags:NUKE.tags,severity:Array.from(NUKE.severity),template_path:NUKE.template_path,rate_limit:NUKE.rate_limit,concurrency:NUKE.concurrency,bulk_size:NUKE.bulk_size,timeout:NUKE.timeout,retries:NUKE.retries}; }
function applyNukeConfig(cfg){ NUKE.modules=cfg.modules||[]; NUKE.tags=cfg.tags||""; NUKE.severity=new Set(cfg.severity||[]); NUKE.template_path=cfg.template_path||""; NUKE.rate_limit=cfg.rate_limit||150; NUKE.concurrency=cfg.concurrency||25; NUKE.bulk_size=cfg.bulk_size||25; NUKE.timeout=cfg.timeout||10; NUKE.retries=cfg.retries||1; buildNukeForm(); }
function filterNukeModules(q){
  const msel=$("nkModules"); if(!msel||!NUKE_META) return;
  const sel=new Set(Array.from(msel.selectedOptions).map(o=>o.value)); const ql=(q||"").toLowerCase();
  const mods=(NUKE_META.modules||[]).filter(m=>!ql||m.path.toLowerCase().includes(ql));
  msel.innerHTML=mods.map(m=>`<option value="${esc(m.path)}" ${sel.has(m.path)||NUKE.modules.includes(m.path)?"selected":""}>${esc(m.path)} (${m.count})</option>`).join("");
}
function buildNukeForm(){
  $("panel").innerHTML=nukeFormHTML();
  $("nkStart").onclick=startNuclei; $("nkStop").onclick=stopNuclei;
  $("nkClearTargets").onclick=()=>{ $("nkTargets").value=""; NUKE.targets=""; };
  const fs=$("nkFromScan"); if(fs) fs.onclick=()=>{ const urls=(scanData.hosts||[]).filter(h=>h.live&&h.url).map(h=>h.url); const cur=$("nkTargets").value.trim(); $("nkTargets").value=(cur?cur+"\n":"")+urls.join("\n"); NUKE.targets=$("nkTargets").value; };
  $("nkProfLoad").onclick=()=>{ const n=$("nkProfileSel").value; if(n&&PROFILES.nuclei[n]) applyNukeConfig(PROFILES.nuclei[n]); };
  $("nkProfSave").onclick=()=>saveProfilePrompt("nuclei", nukeConfig(), "nkProfileSel");
  $("nkProfDel").onclick=()=>deleteProfileSel("nuclei","nkProfileSel");
  const ms=$("nkModSearch"); if(ms) ms.oninput=()=>{ filterNukeModules(ms.value); refocusEl("nkModSearch"); };
  loadProfiles().then(()=>fillProfileSel("nkProfileSel","nuclei"));
  loadNukeMeta();
}
function renderNuclei(){ if(!$("nkForm")) buildNukeForm(); renderNukeResults(); }
let nkRenderPending=false;
function scheduleNukeRender(){ if(nkRenderPending) return; nkRenderPending=true; setTimeout(()=>{ nkRenderPending=false; if(activeTab==="nuclei") renderNukeResults(); },350); }

function startNuclei(){
  syncNukeState();
  if(!NUKE.targets.trim()){ alert("Enter at least one target URL (or load live hosts from a scan)."); return; }
  if(NUKE_META && !NUKE_META.installed){ alert("nuclei is not installed."); return; }
  NUKE.rows=[]; NUKE.running=true; if(NUKE.es){ try{NUKE.es.close();}catch(e){} }
  updateNukeButtons(); renderNukeResults();
  const body={ targets:NUKE.targets, templates:NUKE.modules, tags:NUKE.tags,
    template_path:NUKE.template_path, severity:Array.from(NUKE.severity),
    rate_limit:NUKE.rate_limit, concurrency:NUKE.concurrency, bulk_size:NUKE.bulk_size,
    timeout:NUKE.timeout, retries:NUKE.retries, deadline:NUKE.deadline, scan_id:currentScanId };
  $("nkPhase").textContent="▸ starting…";
  fetch("/api/nuclei",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
    .then(r=>r.json()).then(res=>{
      if(!res.job_id){ $("nkPhase").textContent="⚠ "+(res.detail||"failed to start"); NUKE.running=false; updateNukeButtons(); return; }
      $("nkPhase").textContent=`▸ scanning ${res.targets} target(s)…`;
      const es=new EventSource(`/api/nuclei/${res.job_id}/events`); NUKE.es=es;
      es.onmessage=(e)=>{ const ev=JSON.parse(e.data);
        if(ev.kind==="phase") $("nkPhase").textContent="▸ "+ev.phase;
        else if(ev.kind==="finding"){ NUKE.rows.push(ev.row); scheduleNukeRender(); }
        else if(ev.kind==="done"){ es.close(); NUKE.running=false; updateNukeButtons();
          const loaded=(ev.loaded!=null)?` · ${ev.loaded} template(s) run`:"";
          const note=ev.note?`  —  ⚠ ${ev.note}`:"";
          $("nkPhase").textContent=`✓ done — ${NUKE.rows.length} finding${NUKE.rows.length===1?"":"s"}${loaded}${ev.saved?" · saved to Findings":""}${ev.truncated?" (capped at 5000)":""}${note}`;
          NUKE.lastNote=ev.note||""; renderNukeResults(); if(ev.saved) refreshFindings(); }
        else if(ev.kind==="error"){ es.close(); NUKE.running=false; updateNukeButtons(); $("nkPhase").textContent="⚠ "+(ev.message||"error"); renderNukeResults(); }
      };
      es.onerror=()=>{ es.close(); NUKE.running=false; updateNukeButtons(); if(!$("nkPhase").textContent.startsWith("✓")) $("nkPhase").textContent="▸ stream ended"; };
    }).catch(()=>{ $("nkPhase").textContent="⚠ failed to start"; NUKE.running=false; updateNukeButtons(); });
}
function stopNuclei(){ if(NUKE.es){ try{NUKE.es.close();}catch(e){} } NUKE.running=false; updateNukeButtons(); $("nkPhase").textContent="■ stopped listening (server finishes under its max-time)"; }
function updateNukeButtons(){ const s=$("nkStart"),t=$("nkStop"); if(s){ s.disabled=NUKE.running; s.textContent=NUKE.running?"scanning…":"▶ Scan"; } if(t) t.disabled=!NUKE.running; }

function renderNukeResults(){
  const out=$("nkOut"); if(!out) return;
  const total=NUKE.rows.length;
  let rows=NUKE.rows.slice();
  if(NUKE.sevFacet.size) rows=rows.filter(r=>NUKE.sevFacet.has(r.severity));
  const f=(NUKE.filter||"").toLowerCase();
  if(f) rows=rows.filter(r=>(r.template||"").toLowerCase().includes(f)||(r.name||"").toLowerCase().includes(f)||(r.url||"").toLowerCase().includes(f)||(r.tags||[]).join(",").toLowerCase().includes(f));
  rows=applyExclude(rows, NUKE.exclude, ["template","name","url","tags"]);
  const sevChips=SEV_ORDER.map(s=>{ const n=NUKE.rows.filter(r=>r.severity===s).length; if(!n&&!NUKE.sevFacet.has(s)) return ""; return `<span class="facet ${NUKE.sevFacet.has(s)?'on':''}" data-nksev="${s}"><span class="sev ${s}">${s}</span> <b>${n}</b></span>`; }).join("");
  let html=`<div class="filterbar" style="margin-top:4px">
      <input id="nkResFilter" type="text" placeholder="filter (keep)…" style="min-width:130px;flex:0 1 220px" value="${esc(NUKE.filter||"")}">
      <input id="nkResExclude" type="text" placeholder="exclude a,b,c…" style="min-width:130px;flex:0 1 220px" value="${esc(NUKE.exclude||"")}" title="hide findings containing ANY of these comma-separated terms">
      <span class="muted">${rows.length} / ${total} shown${NUKE.running?' · <span style="color:var(--bad)">scanning…</span>':''}</span>
      <div style="margin-left:auto"><button class="ghost sm" id="nkExport" ${total?"":"disabled"}>⬇ Export</button></div>
    </div>
    <div class="facets">${sevChips}</div>`;
  if(!total){
    const noteHtml=(!NUKE.running&&NUKE.lastNote)?`<p class="expbox" style="border-color:#d2992244;color:var(--warn)">⚠ ${esc(NUKE.lastNote)}</p>`:"";
    html+=noteHtml+`<p class="muted">${NUKE.running?"Scanning… findings stream in here as nuclei reports them.":"No findings yet. Add targets, optionally pick module folders / tags / severity above, then hit <b>Scan</b>. Leaving template selection blank runs <b>every</b> template (slow — narrow it down for speed). Tip: <code>http/technologies</code>, <code>exposed-panels</code> and most <code>exposures</code> are <b>info</b> severity — uncheck the severity boxes (or add info) to see them."}</p>`;
  } else {
    const sr=r=>SEV_ORDER.indexOf(r.severity); rows.sort((a,b)=>sr(a)-sr(b)||(a.template||"").localeCompare(b.template||""));
    const shown=rows.slice(0,3000);
    html+=`<table><thead><tr><th>Severity</th><th>Template</th><th>Name</th><th>Matched URL</th><th>Tags</th></tr></thead><tbody>`+
      shown.map(r=>`<tr>
        <td><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></td>
        <td class="mono">${esc(r.template)}</td>
        <td>${esc(r.name)}</td>
        <td class="mono"><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc((r.url||"").length>90?r.url.slice(0,90)+'…':r.url)}</a></td>
        <td class="muted">${(r.tags||[]).slice(0,5).map(t=>`<span class="tag">${esc(t)}</span>`).join("")}</td></tr>`).join("")+`</tbody></table>`;
    if(shown.length<rows.length) html+=`<p class="muted">Showing first ${shown.length} of ${rows.length} — refine the filter.</p>`;
  }
  out.innerHTML=html;
  const rf=$("nkResFilter"); if(rf) rf.oninput=()=>{ NUKE.filter=rf.value; renderNukeResults(); refocusEl("nkResFilter"); };
  const nex=$("nkResExclude"); if(nex) nex.oninput=()=>{ NUKE.exclude=nex.value; renderNukeResults(); refocusEl("nkResExclude"); };
  out.querySelectorAll("[data-nksev]").forEach(el=>el.onclick=()=>{ const s=el.dataset.nksev; NUKE.sevFacet.has(s)?NUKE.sevFacet.delete(s):NUKE.sevFacet.add(s); renderNukeResults(); });
  const ex=$("nkExport"); if(ex) ex.onclick=()=>dl(`nuclei_findings.txt`, NUKE.rows.map(r=>`[${r.severity}] ${r.template} ${r.url}`).join("\n"));
}

// ========================================================================
// Auth + scope
// ========================================================================
async function initAuth(){
  let s; try{ s=await (await _origFetch("/api/auth/status")).json(); }catch(e){ return true; }
  AUTH_REQUIRED=!!s.auth_required; ALLOW_REG=!!s.allow_registration;
  renderAuthBox(s);
  if(s.auth_required && !s.authenticated){ authMode = ALLOW_REG?"register":"login"; showLogin(); return false; }
  return true;
}
function renderAuthBox(s){
  const box=$("authBox"); if(!box) return;
  if(s && s.auth_required && s.authenticated && s.user){
    box.innerHTML=`👤 <b>${esc(s.user)}</b> · <a href="#" id="logoutLink">logout</a>`;
    const l=$("logoutLink"); if(l) l.onclick=(e)=>{ e.preventDefault(); logout(); };
  } else box.innerHTML="";
}
function updateAuthModeUI(){
  const reg=authMode==="register";
  $("loginTitle").textContent = reg?"Create your ReconMind account":"Sign in to ReconMind";
  $("loginSub").textContent = reg?"Set up the first account for this instance.":"This instance requires an account.";
  $("authSubmit").textContent = reg?"Create account":"Sign in";
  $("authToggle").textContent = reg?"Have an account? Sign in":"Create an account";
  $("authToggle").style.display = ALLOW_REG ? "" : "none";
  $("authPass").setAttribute("autocomplete", reg?"new-password":"current-password");
}
function showLogin(msg){
  if(!AUTH_REQUIRED) return;
  $("authErr").textContent=msg||""; updateAuthModeUI();
  $("loginOverlay").classList.add("show");
  const u=$("authUser"); if(u && !u.value) u.focus();
}
function toggleAuthMode(){ authMode = authMode==="register"?"login":"register"; $("authErr").textContent=""; updateAuthModeUI(); }
async function doAuthSubmit(){
  const u=$("authUser").value.trim(), p=$("authPass").value;
  if(!u||!p){ $("authErr").textContent="Enter a username and password."; return; }
  const ep = authMode==="register"?"/api/auth/register":"/api/auth/login";
  $("authSubmit").disabled=true;
  try{
    let r=await _origFetch(ep,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
    let d=await r.json().catch(()=>({}));
    if(!r.ok){ $("authErr").textContent=d.detail||"Failed."; $("authSubmit").disabled=false; return; }
    if(authMode==="register"){
      r=await _origFetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
      if(!r.ok){ authMode="login"; updateAuthModeUI(); $("authErr").textContent="Account created — please sign in."; $("authSubmit").disabled=false; return; }
    }
    $("authSubmit").disabled=false; $("authPass").value="";
    $("loginOverlay").classList.remove("show");
    await initAuth(); startApp();
  }catch(e){ $("authErr").textContent="Network error."; $("authSubmit").disabled=false; }
}
async function logout(){ try{ await _origFetch("/api/auth/logout",{method:"POST"}); }catch(e){} location.reload(); }

async function openScope(){
  try{ const d=await (await fetch("/api/scope")).json(); $("scopeText").value=(d.in_scope||[]).join("\n"); }catch(e){ $("scopeText").value=""; }
  $("scopeMsg").textContent=""; $("scopeOverlay").classList.add("show");
}
async function saveScope(){
  const items=$("scopeText").value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  try{ const d=await (await fetch("/api/scope",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({in_scope:items})})).json();
    $("scopeText").value=(d.in_scope||[]).join("\n"); $("scopeMsg").textContent=`Saved — ${(d.in_scope||[]).length} host(s) in scope`+((d.in_scope||[]).length?".":" (unrestricted).");
  }catch(e){ $("scopeMsg").textContent="Save failed."; }
}

// ---------- auth admin (toggle + manage users) ----------
async function refreshAuthBox(){ try{ const s=await (await _origFetch("/api/auth/status")).json(); AUTH_REQUIRED=!!s.auth_required; renderAuthBox(s); }catch(e){} }
async function openAuthAdmin(){ await renderAuthAdmin(); $("authAdminMsg").textContent=""; $("authAdminOverlay").classList.add("show"); }
async function renderAuthAdmin(){
  let d; try{ d=await (await fetch("/api/auth/users")).json(); }catch(e){ d={enabled:false,users:[]}; }
  const on=!!d.enabled;
  $("authState").innerHTML = on?'<span class="yes">● ON</span>':'<span class="no">○ OFF</span>';
  $("authStateNote").textContent = on?"Login required on every API route.":"Open — anyone who can reach this URL can use it.";
  $("authToggleBtn").textContent = on?"Turn OFF":"Turn ON";
  $("authUsersWrap").style.display = on?"":"none";
  $("auUserList").innerHTML = (d.users||[]).length ? (d.users||[]).map(u=>`<div class="histrow"><div class="hd">👤 ${esc(u.username)}</div><button class="ghost sm" data-rmuser="${esc(u.username)}" style="color:var(--bad)">remove</button></div>`).join("") : '<p class="muted">No accounts yet.</p>';
  $("auUserList").querySelectorAll("[data-rmuser]").forEach(b=>b.onclick=()=>removeUser(b.dataset.rmuser));
}
async function toggleAuth(){
  const on=$("authState").textContent.includes("ON");
  if(on && !confirm("Turn authentication OFF? Anyone who can reach this server will be able to use it.")) return;
  try{ await fetch("/api/auth/toggle",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({on:!on})}); }catch(e){}
  await renderAuthAdmin(); await refreshAuthBox();
  $("authAdminMsg").textContent = on ? "Auth is OFF." : "Auth is ON. If you have no account yet, add one below (or close & refresh to register).";
}
async function addUser(){
  const u=$("auNewUser").value.trim(), p=$("auNewPass").value;
  if(!u||!p){ $("authAdminMsg").textContent="Enter a username and password."; return; }
  const r=await fetch("/api/auth/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){ $("authAdminMsg").textContent=d.detail||"Could not add user."; return; }
  $("auNewUser").value=""; $("auNewPass").value=""; $("authAdminMsg").textContent="✓ user added."; renderAuthAdmin();
}
async function removeUser(username){
  if(!confirm(`Remove account "${username}"?`)) return;
  const r=await fetch(`/api/auth/users/${encodeURIComponent(username)}`,{method:"DELETE"});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){ $("authAdminMsg").textContent=d.detail||"Could not remove."; return; }
  $("authAdminMsg").textContent="✓ removed."; renderAuthAdmin();
}

// ---------- monitoring ----------
async function saveWebhook(){
  const url=$("monWebhook").value.trim();
  try{ await fetch("/api/monitors/webhook",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})}); $("monWebhookMsg").textContent=url?"✓ saved":"cleared"; setTimeout(()=>$("monWebhookMsg").textContent="",1500); }
  catch(e){ $("monWebhookMsg").textContent="save failed"; }
}
async function openMonitor(){ await renderMonitors(); try{ const d=await (await fetch("/api/monitors")).json(); $("monWebhook").value=d.webhook||""; }catch(e){} $("monitorOverlay").classList.add("show"); }
async function renderMonitors(){
  let data; try{ data=await (await fetch("/api/monitors")).json(); }catch(e){ return; }
  const running=new Set(data.running||[]); const ms=data.monitors||[];
  $("monList").innerHTML = ms.length ? ms.map(m=>{
    const nc=m.new_counts||{};
    const totalNew=(nc.subdomains||0)+(nc.live||0)+(nc.endpoints||0)+(nc.takeovers||0);
    const last=m.last_run?new Date(m.last_run*1000).toLocaleString():"never";
    const st=running.has(m.id)?'<span style="color:var(--warn)">running…</span>':(m.last_status==="error"?'<span style="color:var(--bad)">error</span>':esc(m.last_status||""));
    const badges = m.last_run ? (totalNew?`<span class="newbadge">+${nc.subdomains||0} subs</span> <span class="newbadge">+${nc.live||0} live</span> <span class="newbadge">+${nc.endpoints||0} eps</span>${nc.takeovers?` <span class="tobadge high">+${nc.takeovers} takeover</span>`:''}`:'<span class="muted">no changes</span>') : '';
    return `<div class="histrow"><div>
      <div class="hd">${esc(m.domain)} <span class="muted">· every ${esc(String(m.interval_hours))}h${m.deep?' · deep':''}</span></div>
      <div class="hc">${m.active?'<span class="yes">● active</span>':'<span class="no">○ paused</span>'} · last: ${esc(last)} · ${st} ${badges}${m.error?` <span style="color:var(--bad)">${esc(m.error)}</span>`:''}</div>
      </div><div style="display:flex;gap:6px">
      <button class="ghost sm" data-run="${m.id}" ${running.has(m.id)?'disabled':''}>Run now</button>
      <button class="ghost sm" data-tgl="${m.id}">${m.active?'Pause':'Resume'}</button>
      <button class="ghost sm" data-del="${m.id}" style="color:var(--bad)">🗑</button>
    </div></div>`;
  }).join("") : `<p class="muted">No monitors yet. Add a target above to start watching it.</p>`;
  $("monList").querySelectorAll("[data-run]").forEach(b=>b.onclick=async()=>{ b.disabled=true; b.textContent="starting…"; try{await fetch(`/api/monitors/${b.dataset.run}/run`,{method:"POST"});}catch(e){} setTimeout(renderMonitors,1500); });
  $("monList").querySelectorAll("[data-tgl]").forEach(b=>b.onclick=async()=>{ try{await fetch(`/api/monitors/${b.dataset.tgl}/toggle`,{method:"POST"});}catch(e){} renderMonitors(); });
  $("monList").querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{ if(!confirm("Stop watching this target?"))return; try{await fetch(`/api/monitors/${b.dataset.del}`,{method:"DELETE"});}catch(e){} renderMonitors(); });
}
async function addMonitor(){
  const domain=$("monDomain").value.trim(); if(!domain){ $("monDomain").focus(); return; }
  const interval=parseFloat($("monInterval").value)||24; const deep=$("monDeep").checked;
  const r=await fetch("/api/monitors",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain,interval_hours:interval,deep})});
  if(!r.ok){ const e=await r.json().catch(()=>({})); alert(e.detail||"Could not add monitor."); return; }
  $("monDomain").value=""; renderMonitors();
}

// ---------- port scanning (🔌 Ports panel) ----------
let PORT = { rows:[] };
async function openPorts(){
  const ips=(scanData&&scanData.ip_assets?scanData.ip_assets.map(r=>r.ip):[]);
  const hosts=(scanData&&scanData.hosts?scanData.hosts.filter(h=>h.live&&h.host).map(h=>h.host):[]);
  const items=ips.map(ip=>({v:ip,ip:true})).concat(hosts.map(h=>({v:h,ip:false})));
  const has=items.length>0;
  $("portsNeedScan").hidden=has; $("portsBody").style.display=has?"":"none"; $("ptStart").disabled=!has;
  $("ptCount").textContent=`(${items.length})`;
  $("ptTargets").innerHTML = has ? items.map(it=>`<label class="chk" style="display:flex;gap:6px"><input type="checkbox" class="ptt" data-v="${esc(it.v)}" data-ip="${it.ip?1:0}" ${it.ip?"checked":""}> <span class="mono">${esc(it.v)}</span> <span class="tag">${it.ip?"IP":"host"}</span></label>`).join("") : '<span class="muted">no IPs or live hosts in this scan</span>';
  PORT.rows=[]; $("ptOut").innerHTML=""; $("ptPhase").textContent="";
  $("ptCustom").style.display = $("ptPreset").value==="custom"?"":"none";
  $("ptSvcWrap").style.display = $("ptEngine").value==="nmap"?"flex":"none";
  $("portsOverlay").classList.add("show");
}
function ptSelected(){ return Array.from(document.querySelectorAll(".ptt:checked")).map(c=>c.dataset.v); }
function resetPt(){ $("ptStart").disabled=false; $("ptStart").textContent="▶ Scan ports"; }
let ptPending=false; function schedulePtRender(){ if(ptPending)return; ptPending=true; setTimeout(()=>{ptPending=false; renderPortResults();},300); }
function renderPortResults(){
  const out=$("ptOut"); if(!out) return;
  if(!PORT.rows.length){ out.innerHTML=`<p class="muted" style="margin-top:8px">${$("ptStart").disabled?"scanning… open ports stream in here.":"No open ports yet."}</p>`; return; }
  const rows=PORT.rows.slice().sort((a,b)=>(a.ip||"").localeCompare(b.ip||"")||(a.port-b.port));
  out.innerHTML=`<div class="muted" style="margin:6px 0">${PORT.rows.length} open port(s)</div><table><thead><tr><th>IP</th><th>Port</th><th>Service / version</th><th>Engine</th></tr></thead><tbody>`+
    rows.slice(0,2000).map(r=>`<tr><td class="mono">${esc(r.ip)}${r.host&&r.host!==r.ip?` <span class="muted">(${esc(r.host)})</span>`:''}</td><td><span class="port">${r.port}</span></td><td class="muted">${esc(r.product||r.service||"")}</td><td><span class="tag">${esc(r.source)}</span></td></tr>`).join("")+`</tbody></table>`;
}
async function startPorts(){
  const targets=ptSelected(); if(!targets.length){ $("ptPhase").textContent="⚠ select at least one target"; return; }
  const body={ scan_id:currentScanId, targets, engine:$("ptEngine").value, preset:$("ptPreset").value,
    ports:$("ptCustom").value, rate:parseInt($("ptRate").value)||1000, concurrency:parseInt($("ptConc").value)||50,
    service:$("ptService").checked, deadline:parseInt($("ptDeadline").value)||300 };
  PORT.rows=[]; $("ptStart").disabled=true; $("ptStart").textContent="scanning…"; $("ptPhase").textContent="▸ starting…"; renderPortResults();
  let r; try{ r=await (await fetch("/api/ports",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json(); }catch(e){ $("ptPhase").textContent="⚠ failed to start"; resetPt(); return; }
  if(!r.job_id){ $("ptPhase").textContent="⚠ "+(r.detail||"failed to start"); resetPt(); return; }
  $("ptPhase").textContent=`▸ scanning ${r.targets} target(s)…`;
  const es=new EventSource(`/api/ports/${r.job_id}/events`);
  es.onmessage=(e)=>{ const ev=JSON.parse(e.data);
    if(ev.kind==="phase") $("ptPhase").textContent="▸ "+ev.phase;
    else if(ev.kind==="result"){ PORT.rows.push(ev.row); schedulePtRender(); }
    else if(ev.kind==="done"){ es.close(); resetPt(); $("ptPhase").textContent=`✓ done — ${ev.ports} open port(s) on ${ev.ips} IP(s)${ev.saved?" · merged into IPs & Services":""}`; renderPortResults(); if(ev.saved) refreshFindings(); }
    else if(ev.kind==="error"){ es.close(); resetPt(); $("ptPhase").textContent="⚠ "+(ev.message||"error"); }
  };
  es.onerror=()=>{ es.close(); resetPt(); if(!$("ptPhase").textContent.startsWith("✓")) $("ptPhase").textContent="▸ stream ended"; };
}

// ---------- multi-host Enumerate ----------
async function openEnumerate(){
  const live=(scanData&&scanData.hosts?scanData.hosts.filter(h=>h.live&&h.url):[]);
  $("enumNeedScan").hidden = live.length>0;
  $("enumBody").style.display = live.length? "":"none";
  $("enumStart").disabled = !live.length;
  $("enumCount").textContent=`(${live.length})`;
  $("enumHosts").innerHTML = live.length ? live.map(h=>`<label class="chk" style="display:flex;gap:6px;align-items:center"><input type="checkbox" class="enh" data-url="${esc(h.url)}" data-x2="${h.status&&h.status<300?1:0}" ${h.status&&h.status<300?"checked":""}> <span class="mono">${esc(h.host)}</span> ${h.status?`<span class="st ${statusClass(h.status)}">${h.status}</span>`:""}</label>`).join("") : `<span class="muted">no live hosts</span>`;
  await loadFuzzMeta();
  const wsel=$("enWordlist"); if(wsel&&FUZZ_META.wordlists){ const groups={}; FUZZ_META.wordlists.forEach(w=>{(groups[w.group]=groups[w.group]||[]).push(w);}); wsel.innerHTML=`<option value="">— choose a wordlist —</option>`+Object.entries(groups).map(([g,ws])=>`<optgroup label="${esc(g)}">`+ws.map(w=>`<option value="${esc(w.path)}">${esc(w.name)} · ${w.lines>=0?w.lines.toLocaleString()+" lines":w.human}</option>`).join("")+`</optgroup>`).join(""); }
  const tsel=$("enTool"); if(tsel&&FUZZ_META.tools){ tsel.innerHTML=(FUZZ_META.tools.tools||[]).map(t=>`<option value="${esc(t.name)}" ${t.available?"":"disabled"}>${esc(t.name)}${t.available?"":" — not installed"}</option>`).join(""); tsel.value=(FUZZ_META.tools.default||"ffuf"); }
  $("enumPhase").textContent="";
  $("enumOverlay").classList.add("show");
}
function enumSelected(){ return Array.from(document.querySelectorAll(".enh:checked")).map(c=>c.dataset.url); }
function resetEnumBtn(){ $("enumStart").disabled=false; $("enumStart").textContent="▶ Enumerate"; }
async function startEnumerate(){
  const hosts=enumSelected();
  if(!hosts.length){ $("enumPhase").textContent="⚠ select at least one host"; return; }
  const caps={dir_brute:$("enDir").checked, params:$("enParams").checked, vhosts:$("enVhost").checked};
  if(!caps.dir_brute && !caps.params && !caps.vhosts){ $("enumPhase").textContent="⚠ enable at least one capability"; return; }
  if((caps.dir_brute||caps.vhosts) && !$("enWordlist").value){ $("enumPhase").textContent="⚠ pick a wordlist (a subdomain list for vhost enum)"; return; }
  const body={ scan_id:currentScanId, hosts, capabilities:caps, wordlist:$("enWordlist").value, tool:$("enTool").value,
    extensions:$("enExt").value, threads:parseInt($("enThreads").value)||40,
    host_concurrency:parseInt($("enConc").value)||3, per_host_deadline:parseInt($("enDeadline").value)||120 };
  $("enumStart").disabled=true; $("enumStart").textContent="running…"; $("enumPhase").textContent="▸ starting…";
  const counts={content:0,params:0};
  let r; try{ r=await (await fetch("/api/enumerate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json(); }catch(e){ $("enumPhase").textContent="⚠ failed to start"; resetEnumBtn(); return; }
  if(!r.job_id){ $("enumPhase").textContent="⚠ "+(r.detail||"failed to start"); resetEnumBtn(); return; }
  const es=new EventSource(`/api/enumerate/${r.job_id}/events`);
  es.onmessage=(e)=>{ const ev=JSON.parse(e.data);
    if(ev.kind==="phase") $("enumPhase").textContent="▸ "+ev.phase;
    else if(ev.kind==="result"){ if(ev.bucket==="content")counts.content++; else counts.params++; }
    else if(ev.kind==="done"){ es.close(); resetEnumBtn(); $("enumPhase").textContent=`✓ done — ${ev.content} content, ${ev.params} param${ev.vhosts?`, ${ev.vhosts} vhost`:""} finding(s)${ev.saved?" · saved to Findings":""}`; if(ev.saved) refreshFindings(); }
    else if(ev.kind==="error"){ es.close(); resetEnumBtn(); $("enumPhase").textContent="⚠ "+(ev.message||"error"); }
  };
  es.onerror=()=>{ es.close(); resetEnumBtn(); if(!$("enumPhase").textContent.startsWith("✓")) $("enumPhase").textContent="▸ stream ended"; };
}

// ---------- boot ----------
function startApp(){ if(_appStarted) return; _appStarted=true; loadTools(); loadLlm(); loadModels(); setInterval(loadLlm,15000); setInterval(()=>{ if($("monitorOverlay").classList.contains("show")) renderMonitors(); }, 5000); }
async function boot(){ if(await initAuth()) startApp(); }

// ---------- wire up ----------
$("scanBtn").onclick=startScan;
$("domain").addEventListener("keydown",e=>{if(e.key==="Enter")startScan();});
$("explainBtn").onclick=explain; $("askBtn").onclick=ask;
$("ask").addEventListener("keydown",e=>{if(e.key==="Enter")ask();});
$("onlyLive").onchange=render; $("onlyParams").onchange=render; $("filter").oninput=render; $("exclude").oninput=render;
$("crawlBtn").onclick=runCrawl;
$("exportBtn").onclick=(e)=>{ e.stopPropagation(); $("exportMenu").classList.toggle("show"); };
$("exportMenu").querySelectorAll("[data-exp]").forEach(a=>a.onclick=()=>doExport(a.dataset.exp));
document.addEventListener("click",()=>$("exportMenu").classList.remove("show"));
$("keysBtn").onclick=openKeys; $("keysClose").onclick=()=>$("keysOverlay").classList.remove("show"); $("keysSave").onclick=saveKeys;
$("keysOverlay").onclick=(e)=>{ if(e.target===$("keysOverlay")) $("keysOverlay").classList.remove("show"); };
$("importBtn").onclick=()=>$("importFile").click(); $("importFile").onchange=importFileChosen;
$("historyBtn").onclick=openHistory; $("historyClose").onclick=()=>$("historyOverlay").classList.remove("show");
$("histRange").onchange=renderHistoryList; $("histOrder").onchange=renderHistoryList; $("histSearch").oninput=renderHistoryList;
$("historyOverlay").onclick=(e)=>{ if(e.target===$("historyOverlay")) $("historyOverlay").classList.remove("show"); };
$("lightbox").onclick=()=>$("lightbox").classList.remove("show");
$("modelSelect").onchange=onModelChange;
$("diffBtn").onclick=openDiff;
$("diffSelect").onchange=(e)=>runDiff(e.target.value);
$("diffExport").onclick=exportDiff;
$("diffClose").onclick=()=>$("diffOverlay").classList.remove("show");
$("diffOverlay").onclick=(e)=>{ if(e.target===$("diffOverlay")) $("diffOverlay").classList.remove("show"); };
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{ document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active")); t.classList.add("active"); activeTab=t.dataset.tab; try{history.replaceState(null,"","#"+activeTab);}catch(e){} render(); });
// Deep-link / bookmark a tab via the URL hash (e.g. …/#fuzzer opens the Fuzzer).
(function initTabFromHash(){ const h=(location.hash||"").slice(1); const el=h&&document.querySelector('.tab[data-tab="'+h+'"]'); if(el){ document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active")); el.classList.add("active"); activeTab=h; render(); } })();
$("portsBtn").onclick=openPorts; $("portsClose").onclick=()=>$("portsOverlay").classList.remove("show"); $("ptStart").onclick=startPorts;
$("portsOverlay").onclick=(e)=>{ if(e.target===$("portsOverlay")) $("portsOverlay").classList.remove("show"); };
$("ptPreset").onchange=()=>{ $("ptCustom").style.display=$("ptPreset").value==="custom"?"":"none"; };
$("ptEngine").onchange=()=>{ $("ptSvcWrap").style.display=$("ptEngine").value==="nmap"?"flex":"none"; };
$("ptAll").onclick=(e)=>{ e.preventDefault(); document.querySelectorAll(".ptt").forEach(c=>c.checked=true); };
$("ptIps").onclick=(e)=>{ e.preventDefault(); document.querySelectorAll(".ptt").forEach(c=>c.checked=c.dataset.ip==="1"); };
$("ptNone").onclick=(e)=>{ e.preventDefault(); document.querySelectorAll(".ptt").forEach(c=>c.checked=false); };
$("enumBtn").onclick=openEnumerate; $("enumClose").onclick=()=>$("enumOverlay").classList.remove("show"); $("enumStart").onclick=startEnumerate;
$("enumOverlay").onclick=(e)=>{ if(e.target===$("enumOverlay")) $("enumOverlay").classList.remove("show"); };
$("enumSelAll").onclick=(e)=>{ e.preventDefault(); document.querySelectorAll(".enh").forEach(c=>c.checked=true); };
$("enumSel2xx").onclick=(e)=>{ e.preventDefault(); document.querySelectorAll(".enh").forEach(c=>c.checked=c.dataset.x2==="1"); };
$("enumSelNone").onclick=(e)=>{ e.preventDefault(); document.querySelectorAll(".enh").forEach(c=>c.checked=false); };
$("authAdminBtn").onclick=openAuthAdmin; $("authAdminClose").onclick=()=>$("authAdminOverlay").classList.remove("show"); $("authToggleBtn").onclick=toggleAuth; $("auAddBtn").onclick=addUser;
$("authAdminOverlay").onclick=(e)=>{ if(e.target===$("authAdminOverlay")) $("authAdminOverlay").classList.remove("show"); };
$("monWebhookSave").onclick=saveWebhook;
$("monitorBtn").onclick=openMonitor; $("monClose").onclick=()=>$("monitorOverlay").classList.remove("show"); $("monAdd").onclick=addMonitor;
$("monDomain").addEventListener("keydown",e=>{ if(e.key==="Enter") addMonitor(); });
$("monitorOverlay").onclick=(e)=>{ if(e.target===$("monitorOverlay")) $("monitorOverlay").classList.remove("show"); };
$("scopeBtn").onclick=openScope; $("scopeClose").onclick=()=>$("scopeOverlay").classList.remove("show"); $("scopeSave").onclick=saveScope;
$("scopeOverlay").onclick=(e)=>{ if(e.target===$("scopeOverlay")) $("scopeOverlay").classList.remove("show"); };
$("authSubmit").onclick=doAuthSubmit; $("authToggle").onclick=toggleAuthMode;
$("authUser").addEventListener("keydown",e=>{ if(e.key==="Enter") $("authPass").focus(); });
$("authPass").addEventListener("keydown",e=>{ if(e.key==="Enter") doAuthSubmit(); });
boot();

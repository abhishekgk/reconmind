"use strict";
// ReconMind front-end. Plain vanilla JS, no build step — easy to read and hack on.

const $ = (id) => document.getElementById(id);
let currentScanId = null;
let scanData = null;
let elapsedTimer = null, startTs = null, pollTimer = null;
let activeTab = "subs";
let priorHosts = new Set();  // hosts from the previous scan of this domain (for "new" badges)
const SORT = {
  subs:{k:"live",d:-1}, ips:{k:"ip",d:1}, asns:{k:"asn",d:1},
  endpoints:{k:"host",d:1}, takeovers:{k:"confidence",d:1}, related:{k:"domain",d:1},
};
const facet = { status:new Set(), shot:false, takeover:false, newOnly:false, hideRev:false };

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
async function openHistory(){
  const data=await (await fetch("/api/scans")).json();
  const scans=data.scans||[];
  $("historyList").innerHTML = scans.length ? scans.map(s=>{
    const c=s.counts||{}, when=s.finished?new Date(s.finished*1000).toLocaleString():"";
    return `<div class="histrow"><div><div class="hd">${esc(s.domain||"?")}</div>
      <div class="hc">${when} · ${c.total||0} subs · ${c.live||0} live · ${c.ips||0} IPs · ${c.takeovers||0} takeovers</div></div>
      <button class="ghost sm" data-load="${esc(s.file)}">Load</button></div>`; }).join("")
    : `<p class="muted">No saved scans yet.</p>`;
  document.querySelectorAll("[data-load]").forEach(b=>b.onclick=()=>loadHistory(b.dataset.load));
  $("historyOverlay").classList.add("show");
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

function applyScan(id, data, partial){
  currentScanId=id; scanData=data;
  const c=data.counts||{};
  $("cTotal").textContent=c.total||0; $("cLive").textContent=c.live||0;
  $("cIps").textContent=c.ips||0; $("cAsns").textContent=c.asns||0;
  $("cRelated").textContent=c.related||0; $("cEndpoints").textContent=c.endpoints||0;
  $("cTakeovers").textContent=c.takeovers||0;
  $("tSubs").textContent=c.total||0; $("tIps").textContent=c.ips||0; $("tAsns").textContent=c.asns||0;
  $("tEndpoints").textContent=c.endpoints||0; $("tTakeovers").textContent=c.takeovers||0; $("tRelated").textContent=c.related||0;
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
  if(!scanData) return;
  $("liveWrap").style.display   = activeTab==="subs" ? "flex" : "none";
  $("paramsWrap").style.display = activeTab==="endpoints" ? "flex" : "none";
  renderFacets();
  if(activeTab==="subs") renderSubs();
  else if(activeTab==="ips") renderIps();
  else if(activeTab==="asns") renderAsns();
  else if(activeTab==="endpoints") renderEndpoints();
  else if(activeTab==="takeovers") renderTakeovers();
  else if(activeTab==="related") renderRelated();
}
function filterText(){ return $("filter").value.trim().toLowerCase(); }
function renderTable(tab, cols, rows, total, cap){
  const st=SORT[tab];
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
function renderFacets(){
  const f=$("facets");
  if(activeTab!=="subs"){ f.innerHTML=""; return; }
  const chip=(id,label,on)=>`<span class="facet ${on?'on':''}" data-facet="${id}">${label}</span>`;
  f.innerHTML = ["2xx","3xx","4xx","5xx"].map(s=>chip("s"+s,s,facet.status.has(s))).join("")
    + chip("shot","📷 has shot",facet.shot) + chip("takeover","⚠ takeover",facet.takeover)
    + chip("new","🆕 new",facet.newOnly) + chip("hiderev","hide reviewed",facet.hideRev);
  f.querySelectorAll("[data-facet]").forEach(el=>el.onclick=()=>{
    const id=el.dataset.facet;
    if(id.startsWith("s")&&id.length===4){ const s=id.slice(1); facet.status.has(s)?facet.status.delete(s):facet.status.add(s); }
    else if(id==="shot") facet.shot=!facet.shot;
    else if(id==="takeover") facet.takeover=!facet.takeover;
    else if(id==="new") facet.newOnly=!facet.newOnly;
    else if(id==="hiderev") facet.hideRev=!facet.hideRev;
    renderSubs(); renderFacets();
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
    {key:"note",label:"Note",nosort:true,cell:r=>`<td><input class="notein" value="${esc(getNote(r.host).note)}" placeholder="…" onchange="saveNote('${esc(r.host)}',this.value)"></td>`},
  ];
  renderTable("subs", cols, rows, scanData.hosts.length);
}
window.toggleRev=(host,el)=>{ const n=getNote(host); setNote(host,{reviewed:!n.reviewed}); el.classList.toggle("on"); el.closest("tr").classList.toggle("reviewed"); };
window.saveNote=(host,val)=>setNote(host,{note:val});
window.openLight=(src)=>{ $("lightboxImg").src=src; $("lightbox").classList.add("show"); };

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
  const f=filterText(); if(f) rows=rows.filter(r=>r.url.toLowerCase().includes(f)||(r.host||"").includes(f)||(r.ext||"").includes(f));
  const cols=[
    {key:"url",label:"URL",val:r=>r.url||"",cell:r=>`<td class="mono"><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.url.length>110?r.url.slice(0,110)+'…':r.url)}</a></td>`},
    {key:"host",label:"Host",val:r=>r.host||"",cell:r=>`<td class="mono muted">${esc(r.host)}</td>`},
    {key:"params",label:"Params",val:r=>r.params?1:0,cell:r=>`<td>${r.params?'<span class="yes">✓</span>':'<span class="no">–</span>'}</td>`},
    {key:"ext",label:"Ext",val:r=>r.ext||"",cell:r=>`<td class="mono muted">${esc(r.ext)}</td>`},
    {key:"source",label:"Source",val:r=>r.source||"",cell:r=>`<td><span class="tag">${esc(r.source)}</span></td>`},
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

// ---------- wire up ----------
$("scanBtn").onclick=startScan;
$("domain").addEventListener("keydown",e=>{if(e.key==="Enter")startScan();});
$("explainBtn").onclick=explain; $("askBtn").onclick=ask;
$("ask").addEventListener("keydown",e=>{if(e.key==="Enter")ask();});
$("onlyLive").onchange=render; $("onlyParams").onchange=render; $("filter").oninput=render;
$("crawlBtn").onclick=runCrawl;
$("exportBtn").onclick=(e)=>{ e.stopPropagation(); $("exportMenu").classList.toggle("show"); };
$("exportMenu").querySelectorAll("[data-exp]").forEach(a=>a.onclick=()=>doExport(a.dataset.exp));
document.addEventListener("click",()=>$("exportMenu").classList.remove("show"));
$("keysBtn").onclick=openKeys; $("keysClose").onclick=()=>$("keysOverlay").classList.remove("show"); $("keysSave").onclick=saveKeys;
$("keysOverlay").onclick=(e)=>{ if(e.target===$("keysOverlay")) $("keysOverlay").classList.remove("show"); };
$("importBtn").onclick=()=>$("importFile").click(); $("importFile").onchange=importFileChosen;
$("historyBtn").onclick=openHistory; $("historyClose").onclick=()=>$("historyOverlay").classList.remove("show");
$("historyOverlay").onclick=(e)=>{ if(e.target===$("historyOverlay")) $("historyOverlay").classList.remove("show"); };
$("lightbox").onclick=()=>$("lightbox").classList.remove("show");
$("modelSelect").onchange=onModelChange;
$("diffBtn").onclick=openDiff;
$("diffSelect").onchange=(e)=>runDiff(e.target.value);
$("diffExport").onclick=exportDiff;
$("diffClose").onclick=()=>$("diffOverlay").classList.remove("show");
$("diffOverlay").onclick=(e)=>{ if(e.target===$("diffOverlay")) $("diffOverlay").classList.remove("show"); };
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{ document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active")); t.classList.add("active"); activeTab=t.dataset.tab; render(); });
loadTools(); loadLlm(); loadModels(); setInterval(loadLlm,15000);

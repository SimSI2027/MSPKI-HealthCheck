# Inline CSS and JavaScript for report.html. Everything is embedded: no external file, font, image or link.

function Get-MspkiReportCss {
    [CmdletBinding()]
    param()
    return @'
:root{--bg:#f5f6f8;--panel:#fff;--ink:#18202b;--muted:#566275;--line:#dce1e9;--accent:#1f4fb8;--code:#eef1f6;
--crit:#a8231a;--crit-bg:#fde7e4;--fail:#a8231a;--fail-bg:#fde7e4;--err:#86206a;--err-bg:#f9e6f3;--warn:#a2470a;--warn-bg:#fff0d9;
--info:#1a56c4;--info-bg:#e6efff;--pass:#0b6a3f;--pass-bg:#e1f5e9;--skip:#4d586a;--skip-bg:#e9edf3;--na:#4d586a;--na-bg:#e9edf3;
--shadow:0 1px 2px rgba(20,30,50,.06),0 2px 8px rgba(20,30,50,.05)}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#111519;--panel:#1a2028;--ink:#e5e9ef;--muted:#9ba7b8;--line:#2b3441;--accent:#8aafff;--code:#222a35;
--crit:#ff8f86;--crit-bg:#3d1d1b;--fail:#ff8f86;--fail-bg:#3d1d1b;--err:#f0a3dc;--err-bg:#38203a;--warn:#ffc177;--warn-bg:#3a2a12;
--info:#9bbcff;--info-bg:#1b2a47;--pass:#7fd9a6;--pass-bg:#15301f;--skip:#aab4c3;--skip-bg:#262e3a;--na:#aab4c3;--na-bg:#262e3a;--shadow:none}}
:root[data-theme=dark]{--bg:#111519;--panel:#1a2028;--ink:#e5e9ef;--muted:#9ba7b8;--line:#2b3441;--accent:#8aafff;--code:#222a35;
--crit:#ff8f86;--crit-bg:#3d1d1b;--fail:#ff8f86;--fail-bg:#3d1d1b;--err:#f0a3dc;--err-bg:#38203a;--warn:#ffc177;--warn-bg:#3a2a12;
--info:#9bbcff;--info-bg:#1b2a47;--pass:#7fd9a6;--pass-bg:#15301f;--skip:#aab4c3;--skip-bg:#262e3a;--na:#aab4c3;--na-bg:#262e3a;--shadow:none}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:64px}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12.5px}
header.top{background:var(--panel);border-bottom:1px solid var(--line);padding:18px 24px 0}
.top h1{margin:0;font-size:20px;letter-spacing:-.01em}.top .sub{color:var(--muted);margin:2px 0 12px}
.top .wrap{display:flex;gap:16px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap}
nav.tabs{display:flex;gap:2px;flex-wrap:wrap;position:sticky;top:0;background:var(--panel);z-index:5;border-bottom:1px solid var(--line);padding:0 24px}
nav.tabs a{padding:10px 14px;color:var(--muted);text-decoration:none;border-bottom:2px solid transparent;font-weight:600}
nav.tabs a:hover,nav.tabs a:focus-visible{color:var(--ink);border-bottom-color:var(--accent);outline:none}
main{max-width:1280px;margin:0 auto;padding:8px 24px 48px}
section{margin-top:28px}section>h2{font-size:17px;margin:0 0 12px;letter-spacing:-.01em}
h3{font-size:14px;margin:18px 0 8px}h4{font-size:12px;margin:14px 0 4px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;box-shadow:var(--shadow)}
.grid{display:grid;gap:14px}.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.tiles{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;text-align:left;cursor:pointer;color:var(--ink);font:inherit;box-shadow:var(--shadow)}
.tile:hover,.tile:focus-visible{border-color:var(--accent);outline:none}
.tile b{display:block;font-size:26px;line-height:1.1;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:12px}
.tile.s-crit b,.tile.s-fail b{color:var(--crit)}.tile.s-warn b{color:var(--warn)}.tile.s-info b{color:var(--info)}.tile.s-pass b{color:var(--pass)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:650;line-height:18px;white-space:nowrap;border:1px solid transparent}
.st-Critical,.st-Fail{color:var(--crit);background:var(--crit-bg)}.st-Error{color:var(--err);background:var(--err-bg)}
.st-Warning{color:var(--warn);background:var(--warn-bg)}.st-Information{color:var(--info);background:var(--info-bg)}
.st-Pass{color:var(--pass);background:var(--pass-bg)}.st-Skipped,.st-NotApplicable{color:var(--skip);background:var(--skip-bg)}
.cf-Confirmed{color:var(--pass);border-color:var(--pass)}.cf-Referenced{color:var(--info);border-color:var(--info)}
.cf-Inferred{color:var(--warn);border-color:var(--warn)}.cf-Unknown{color:var(--skip);border-color:var(--skip)}
.chip{display:inline-block;background:var(--code);border-radius:5px;padding:0 6px;margin:1px 3px 1px 0;font-size:11.5px;color:var(--muted);font-family:ui-monospace,Consolas,monospace}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--skip-bg);margin:6px 0}
.bar i{display:block;height:100%}.bar .c-Confirmed{background:var(--pass)}.bar .c-Referenced{background:var(--info)}.bar .c-Inferred{background:var(--warn)}.bar .c-Unknown{background:var(--skip)}
.legend span{margin-right:14px;white-space:nowrap}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:650}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.exit{display:flex;gap:14px;align-items:center}.exit .code{font-size:34px;font-weight:750;min-width:54px;text-align:center;border-radius:10px;padding:2px 10px}
.exit-0 .code{background:var(--pass-bg);color:var(--pass)}.exit-2 .code{background:var(--info-bg);color:var(--info)}.exit-3 .code{background:var(--warn-bg);color:var(--warn)}
.exit-4 .code{background:var(--crit-bg);color:var(--crit)}.exit-5 .code,.exit-6 .code{background:var(--err-bg);color:var(--err)}
.muted{color:var(--muted)}.small{font-size:12px}.note{border-left:3px solid var(--accent);padding:6px 12px;background:var(--code);border-radius:0 6px 6px 0;margin:10px 0}
.warnbox{border-left:3px solid var(--warn);padding:6px 12px;background:var(--warn-bg);color:var(--ink);border-radius:0 6px 6px 0;margin:10px 0}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.toolbar input[type=search],.toolbar select{font:inherit;padding:6px 9px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink);min-width:0}
.toolbar input[type=search]{flex:1 1 240px}
button.chipbtn,button.btn{font:inherit;font-size:12.5px;padding:4px 10px;border-radius:999px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}
button.chipbtn[aria-pressed=true]{background:var(--accent);color:var(--bg);border-color:var(--accent)}
button.btn{border-radius:7px}button:focus-visible,summary:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.count{margin-left:auto;color:var(--muted)}
details.f{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:6px 0}
details.f[open]{box-shadow:var(--shadow)}details.f>summary{cursor:pointer;padding:8px 12px;display:grid;grid-template-columns:56px 84px minmax(110px,150px) 94px 90px 1fr;gap:8px;align-items:baseline;list-style:none}
details.f>summary::-webkit-details-marker{display:none}.f .id{font-family:ui-monospace,Consolas,monospace;color:var(--muted);font-size:12px}
.f .msg{overflow-wrap:anywhere}.f .code{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--muted)}
.fd{padding:2px 14px 14px;border-top:1px solid var(--line)}.fd dl{display:grid;grid-template-columns:120px 1fr;gap:3px 12px;margin:10px 0}
.fd dt{color:var(--muted);font-size:12px}.fd dd{margin:0;overflow-wrap:anywhere}.fd ul{margin:2px 0 0;padding-left:18px}.fd li{overflow-wrap:anywhere;margin:1px 0}
.layers{display:flex;flex-wrap:wrap;gap:6px}.layers span{font-size:11.5px;border:1px solid var(--line);border-radius:6px;padding:1px 7px;color:var(--muted)}
.layers .l-Pass{color:var(--pass);border-color:var(--pass)}.layers .l-Fail,.layers .l-Timeout,.layers .l-Error,.layers .l-PermissionDenied{color:var(--crit);border-color:var(--crit)}
.layers .l-Warning{color:var(--warn);border-color:var(--warn)}
.dg{margin-top:14px;padding:10px 14px 12px;border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;background:var(--code)}
.dg h4{margin-top:0}.dg p{margin:4px 0}.dgt{font-weight:600}.dgb{color:var(--muted);font-size:12.5px}
.dgc{margin:8px 0 0;padding-left:20px}.dgc>li{margin:10px 0;padding-bottom:8px;border-bottom:1px dashed var(--line)}.dgc>li:last-child{border-bottom:0}
.dgh{margin-bottom:2px}.dgl{font-size:11.5px;border-radius:999px;padding:1px 8px;border:1px solid var(--line);color:var(--muted);margin-left:6px;white-space:nowrap}
.dgl-Mostlikely,.dgl-Mostcommon{color:var(--pass);border-color:var(--pass);background:var(--pass-bg)}.dgl-Likely,.dgl-Common{color:var(--info);border-color:var(--info)}
.dgk{display:block;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-top:6px}
.dgo{background:var(--info-bg);border-radius:6px;padding:2px 10px 4px;margin-top:6px}.dgs code{overflow-wrap:anywhere;font-size:11.5px}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:20px;border-left:1px dashed var(--line)}ul.tree{padding-left:0;border:0}
.tree li{margin:3px 0}.tree details>summary{cursor:pointer;padding:4px 8px;border-radius:6px;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.tree details>summary:hover{background:var(--code)}.ntype{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);min-width:78px}
.nlabel{font-weight:600;overflow-wrap:anywhere}.nd{margin:2px 0 8px 94px;color:var(--muted);font-size:12.5px;overflow-wrap:anywhere}.nd div{margin:1px 0}
.nd a{margin-right:8px}.below{font-size:11.5px;color:var(--muted)}.hide{display:none!important}
.kv{display:grid;grid-template-columns:170px 1fr;gap:3px 14px}.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
footer{margin:40px 24px;color:var(--muted);font-size:12px;text-align:center}
@media (max-width:760px){main,header.top{padding-left:14px;padding-right:14px}nav.tabs{padding:0 14px}details.f>summary{grid-template-columns:1fr 1fr;row-gap:2px}
details.f>summary .msg{grid-column:1/-1}.nd{margin-left:12px}.kv,.fd dl{grid-template-columns:1fr}}
@media print{nav.tabs,.toolbar,.tile{display:none}.tile-print{display:block}details>*{display:block!important}body{background:#fff}}
'@
}

function Get-MspkiReportScript {
    [CmdletBinding()]
    param()
    return @'
(function(){
"use strict";
function $(s,r){return (r||document).querySelector(s);}
function $$(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s));}
var items=$$("details.f"),state={q:"",status:{},cat:"",conf:"",scope:"",code:""};
var count=$("#fcount");
function activeStatuses(){return Object.keys(state.status).filter(function(k){return state.status[k];});}
function apply(){
  var act=activeStatuses(),q=state.q.toLowerCase(),shown=0;
  items.forEach(function(el){
    var d=el.dataset,ok=true;
    if(act.length&&act.indexOf(d.status)<0)ok=false;
    if(ok&&state.cat&&d.category!==state.cat)ok=false;
    if(ok&&state.conf&&d.confidence!==state.conf)ok=false;
    if(ok&&state.scope&&d.scope!==state.scope)ok=false;
    if(ok&&state.code&&d.code!==state.code)ok=false;
    if(ok&&q&&d.search.indexOf(q)<0)ok=false;
    el.classList.toggle("hide",!ok);
    if(ok)shown++;
  });
  if(count)count.textContent="Showing "+shown+" of "+items.length+" findings";
  $$("button.chipbtn[data-status]").forEach(function(b){b.setAttribute("aria-pressed",state.status[b.dataset.status]?"true":"false");});
}
function setStatuses(list){state.status={};list.forEach(function(s){state.status[s]=true;});apply();}
var search=$("#fsearch");if(search)search.addEventListener("input",function(){state.q=this.value;apply();});
[["#fcat","cat"],["#fconf","conf"],["#fscope","scope"],["#fcode","code"]].forEach(function(p){
  var el=$(p[0]);if(el)el.addEventListener("change",function(){state[p[1]]=this.value;apply();});});
$$("button.chipbtn[data-status]").forEach(function(b){b.addEventListener("click",function(){
  state.status[this.dataset.status]=!state.status[this.dataset.status];apply();});});
var reset=$("#freset");if(reset)reset.addEventListener("click",function(){
  state={q:"",status:{},cat:"",conf:"",scope:"",code:""};
  if(search)search.value="";["#fcat","#fconf","#fscope","#fcode"].forEach(function(s){var e=$(s);if(e)e.value="";});apply();});
var onlyProblems=$("#fproblems");if(onlyProblems)onlyProblems.addEventListener("click",function(){
  setStatuses(["Critical","Fail","Error","Warning"]);});
function allDetails(open){items.forEach(function(el){el.open=open;});}
var ex=$("#fexpand");if(ex)ex.addEventListener("click",function(){allDetails(true);});
var co=$("#fcollapse");if(co)co.addEventListener("click",function(){allDetails(false);});
$$("button.tile[data-filter]").forEach(function(b){b.addEventListener("click",function(){
  var f=this.dataset.filter;setStatuses(f?f.split(","):[]);var s=$("#findings");if(s)s.scrollIntoView();});});
function openFinding(){
  var id=decodeURIComponent((location.hash||"").slice(1));if(!id||id.charAt(0)!=="F")return;
  var el=document.getElementById(id);if(!el)return;
  el.classList.remove("hide");el.open=true;el.scrollIntoView({block:"center"});
}
window.addEventListener("hashchange",openFinding);openFinding();
var tree=$("#tree");
function treeProblems(on){$$("li.node",tree).forEach(function(li){li.classList.toggle("hide",on&&li.dataset.problem!=="1");});}
var tp=$("#tproblems");if(tp)tp.addEventListener("change",function(){treeProblems(this.checked);});
var te=$("#texpand");if(te)te.addEventListener("click",function(){$$("details",tree).forEach(function(d){d.open=true;});});
var tc=$("#tcollapse");if(tc)tc.addEventListener("click",function(){$$("details",tree).forEach(function(d,i){d.open=(i===0);});});
var theme=$("#theme");if(theme)theme.addEventListener("click",function(){
  var r=document.documentElement,dark=r.getAttribute("data-theme")==="dark"||(!r.getAttribute("data-theme")&&window.matchMedia("(prefers-color-scheme: dark)").matches);
  r.setAttribute("data-theme",dark?"light":"dark");});
apply();
})();
'@
}

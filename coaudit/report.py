"""Standalone report renderer: no server, CDN, or external script required."""
import html
import json
import re


def render_html(result):
    payload = json.dumps(result, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    title = html.escape(str(result.get("name", "Audit")))
    slots = {"__TITLE__": title, "__DATA__": payload}
    return re.sub(r"__TITLE__|__DATA__", lambda match: slots[match[0]], TEMPLATE)


TEMPLATE = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ROS2-CoAudit · __TITLE__</title>
<style>
:root{color-scheme:light;--ink:#18303a;--muted:#536974;--line:#dbe4e7;--teal:#006d70}
*{box-sizing:border-box}body{font:15px/1.65 system-ui,"Microsoft YaHei",sans-serif;margin:0;background:#f3f6f7;color:var(--ink)}
main{max-width:1220px;margin:auto;padding:36px 30px}header{border-bottom:3px solid var(--teal);padding:0 0 22px;margin-bottom:26px}
.eyebrow{letter-spacing:.16em;font-size:12px;color:var(--teal);font-weight:700}h1{font-size:30px;margin:10px 0}h2{font-size:20px;margin:0 0 12px}h3{font-size:16px}
.muted,small{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card,section{background:white;border:1px solid var(--line);border-radius:10px;padding:22px;margin-bottom:18px}
.card strong{display:block;font-size:20px;margin-top:12px}.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:700;background:#edf1f3}
.PASS,.MODEL_PASS{color:#00624d;background:#e4f3ed}.FAIL,.BLOCK,.INPUT_ERROR{color:#a32626;background:#fce9e7}.UNKNOWN,.REVIEW,.INCOMPLETE{color:#805600;background:#fff1d6}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;border-bottom:1px solid var(--line);padding:10px 9px;vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);font-weight:600;background:#f8fafb}
.scroll{overflow-x:auto}input,select,button{font:inherit;border:1px solid #b7c9cf;border-radius:5px;padding:7px 10px;background:white;color:var(--ink)}input{width:min(430px,100%)}button{cursor:pointer}summary{cursor:pointer;font-weight:600}
pre{font:12px/1.6 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7f8;padding:14px;border-radius:5px;max-height:500px;overflow:auto}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.pill{font-size:12px;color:var(--muted)}footer{font-size:12px;color:var(--muted);padding:10px 0 30px}
@media(max-width:760px){main{padding:20px 14px}.cards{grid-template-columns:1fr}h1{font-size:24px}}
@media print{body{background:white}main{padding:0}.card,section{break-inside:avoid}button,input,select{display:none}pre{max-height:none}.cards{grid-template-columns:repeat(3,1fr)}}
</style><main><header><div class="eyebrow">ROS2-CoAudit / OFFLINE EVIDENCE REVIEW</div><h1>__TITLE__</h1>
<p class="muted">配置、源策略权限与任务约束联合审计 · v1.0.0</p><div id="decision"></div>
<p class="muted">MODEL_PASS 仅表示本次输入与受支持模型满足检查项。它不验证运行时身份、DDS 执行、消息送达或机器人停止。</p></header>
<div class="cards" id="cards"></div><section><h2>更新前后检查</h2><div class="scroll"><table id="comparison"></table></div></section>
<section><h2>任务恢复路径</h2><div class="scroll"><table id="paths"></table></div></section>
<section><h2>权限证据下钻</h2><div class="row"><select id="version" aria-label="版本"><option value="after">更新后</option><option value="before">更新前</option></select><input id="filter" placeholder="筛选资源、节点或原因" aria-label="筛选权限证据"></div><p class="pill">request / reply 表示 SROS2 服务客户端 / 服务端角色。不是单个 DDS 请求包或响应包。</p><div class="scroll"><table id="capabilities"></table></div></section>
<section><h2>任务事件与期限</h2><div id="trace"></div></section>
<section><h2>配置检查与禁止授权</h2><div id="checks"></div></section>
<section><h2>可复核证据</h2><p class="muted">SHA-256 固定本次读取的字节内容，不认证来源或运行时真实性。</p><div class="scroll"><table id="evidence"></table></div></section>
<section><h2>完整结果与边界</h2><div id="errors"></div><ul id="limits"></ul><button id="download">下载结果 JSON</button><details><summary>查看完整结构化结果</summary><pre id="raw"></pre></details></section>
<footer>本报告为本地静态文件；全部筛选在浏览器内完成。</footer></main>
<script id="audit-data" type="application/json">__DATA__</script><script>
'use strict';
const r=JSON.parse(document.getElementById('audit-data').textContent),d=r.domains||{};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge=v=>'<span class="badge '+esc(v)+'">'+esc(v)+'</span>';
const table=(headers,rows)=>'<thead><tr>'+headers.map(x=>'<th>'+esc(x)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(x=>'<td>'+x+'</td>').join('')+'</tr>').join('')+'</tbody>';
document.getElementById('decision').innerHTML=badge(r.decision)+' <span class="pill">输入状态：'+esc(r.input_status)+'</span>';
const c=d.PROTOCOL_COVERAGE?.correlated?.verdicts||{};
const metrics=[['当前配置声明',d.CONFIGURATION?.after?.verdict],['禁止授权约束',d.AUTHORIZATION?.verdict],['更新后通信覆盖',c.after_absolute_recovery_communication?.verdict],['无新增通信退化',c.no_new_recovery_communication_regression?.verdict],['日志取消期限',d.TRACE_OBLIGATION?.verdict],['任务迁移前提',d.CONFIGURATION?.migration?.verdict]];
document.getElementById('cards').innerHTML=metrics.map(([n,v])=>'<div class="card">'+esc(n)+'<strong>'+badge(v||'UNKNOWN')+'</strong></div>').join('');
document.getElementById('comparison').innerHTML=table(['性质','更新前','更新后'],[['配置声明',badge(d.CONFIGURATION?.before?.verdict||'UNKNOWN'),badge(d.CONFIGURATION?.after?.verdict||'UNKNOWN')],['禁止授权约束',badge(d.AUTHORIZATION?.before?.verdict||'UNKNOWN'),badge(d.AUTHORIZATION?.after?.verdict||'UNKNOWN')],['绝对恢复通信覆盖',badge(c.before_absolute_recovery_communication?.verdict||'UNKNOWN'),badge(c.after_absolute_recovery_communication?.verdict||'UNKNOWN')]]);
const worlds=d.PROTOCOL_COVERAGE?.world_evaluations||{};
const pathRows=['before','after'].flatMap(v=>(worlds[v]||[]).flatMap(w=>w.obligations.map(o=>{
  const path=o.authorized_path??o.possible_path;
  const witness=path===null?'没有候选路径':path.length===0?'起点已是目标':path.join(' → ');
  const value=o.value===true?'PASS':o.value===false?'FAIL':'UNKNOWN';
  return [esc(v==='before'?'更新前':'更新后'),esc(o.obligation_id),badge(value),esc(witness)];
})));
document.getElementById('paths').innerHTML=table(['版本','持续义务','覆盖','已授权或候选路径'],pathRows);
function capabilities(){const version=document.getElementById('version').value,q=document.getElementById('filter').value.toLowerCase();const rows=(r.capability_evidence?.[version]||[]).filter(x=>JSON.stringify(x).toLowerCase().includes(q));document.getElementById('capabilities').innerHTML=table(['节点 / Enclave','资源 / 角色','权限值','来源与原因'],rows.map(x=>[esc(x.node)+'<br>'+esc(x.enclave),esc(x.resource)+'<br>'+esc(x.operation),badge(x.value===true?'PASS':x.value===false?'FAIL':'UNKNOWN'),esc((x.sources||[]).join('; '))+'<br>'+esc((x.reasons||[]).join('; '))]));}
document.getElementById('version').addEventListener('change',capabilities);document.getElementById('filter').addEventListener('input',capabilities);capabilities();
const trace=d.TRACE_OBLIGATION||{};document.getElementById('trace').innerHTML='<p>'+badge(trace.verdict||'UNKNOWN')+' '+esc(trace.reason)+'</p>'+(trace.obligations||[]).map(o=>'<details open><summary>'+esc(o.goal_id||o.id)+' '+badge(o.verdict)+'</summary><pre>'+esc(JSON.stringify(o,null,2))+'</pre></details>').join('');
document.getElementById('checks').innerHTML=['CONFIGURATION','AUTHORIZATION'].map(k=>'<details><summary>'+esc(k)+'</summary><pre>'+esc(JSON.stringify(d[k]||{},null,2))+'</pre></details>').join('');
document.getElementById('evidence').innerHTML=table(['文件','字节数','SHA-256'],(r.evidence||[]).map(x=>[esc(x.path),esc(x.bytes),esc(x.sha256)]));
document.getElementById('errors').textContent=(r.input_errors||[]).join('; ');document.getElementById('limits').innerHTML=(r.limitations||[]).map(x=>'<li>'+esc(x)+'</li>').join('');document.getElementById('raw').textContent=JSON.stringify(r,null,2);
document.getElementById('download').addEventListener('click',()=>{const u=URL.createObjectURL(new Blob([JSON.stringify(r,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=u;a.download='audit-result.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)});
</script></html>'''

export const ADMIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>URLCheck unlock codes</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f6f4fa;color:#222}
header{background:#7C2FC9;color:#fff;padding:12px 20px;display:flex;justify-content:space-between}
main{max-width:1100px;margin:20px auto;padding:0 16px}
.card{background:#fff;border-radius:8px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 3px #0002}
label{display:block;margin:8px 0 2px;font-weight:600}
input,select,textarea{width:100%;padding:8px;box-sizing:border-box;font-size:15px}
button{background:#7C2FC9;color:#fff;border:0;border-radius:4px;padding:9px 16px;font-size:15px;cursor:pointer;margin-top:12px}
button.secondary{background:#888}
#code{font:bold 34px Consolas,monospace;letter-spacing:4px;padding:10px 0}
.err{color:#b00020}.muted{color:#666;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:5px;border-bottom:1px solid #eee;vertical-align:top}
.active{color:#0a7d2c;font-weight:600}.redeemed{color:#555}.expired{color:#999}.revoked{color:#b00020}
</style></head><body>
<header><b>URLCheck — helpdesk unlock codes</b><span id="me"></span></header>
<main>
<div class="card">
 <form id="f">
  <label for="ticket">Ticket number (required)</label><input id="ticket" placeholder="TK-15345" required>
  <label for="url">Blocked URL or site</label><input id="url" placeholder="https://app.example.co.uk/login?..." required>
  <label for="reason">Reason / what the user told you</label><textarea id="reason" rows="2"></textarea>
  <label for="ttl">Unlock lasts</label>
  <select id="ttl"><option value="3600">1 hour</option><option value="14400" selected>4 hours</option><option value="28800">8 hours</option></select>
  <button type="submit">Generate code</button>
 </form>
 <p class="muted">Code works once, on any one device, only for that site, and must be entered within 15 minutes. Read it to the user by phone/Teams — never email or chat it. Confirm the site is genuinely needed before issuing.</p>
 <div id="out" hidden><div class="muted">Unlock code for <b id="oorigin"></b> (ticket <b id="oticket"></b>) — redeem before <b id="oexp"></b></div><div id="code"></div></div>
 <div id="err" class="err"></div>
</div>
<div class="card"><b>Recent codes</b> <button class="secondary" id="refresh" type="button">Refresh</button>
<table><thead><tr><th>Created</th><th>Ticket</th><th>Site</th><th>Issuer</th><th>Status</th><th>Redeemed by</th><th></th></tr></thead><tbody id="rows"></tbody></table></div>
</main>
<script>
const H={'content-type':'application/json','x-urlcheck-admin':'1'};
const t=(ms)=>ms?new Date(ms).toLocaleString('en-GB',{timeZone:'Europe/London'}):'';
function td(tr,txt,cls){const c=document.createElement('td');c.textContent=txt==null?'':String(txt);if(cls)c.className=cls;tr.appendChild(c);return c;}
async function me(){const r=await fetch('/admin/api/me');const j=await r.json();document.getElementById('me').textContent=j.email||'';}
async function load(){
 const r=await fetch('/admin/api/codes');const j=await r.json();const tb=document.getElementById('rows');tb.replaceChildren();
 for(const c of (j.codes||[])){const tr=document.createElement('tr');
  td(tr,t(c.created_at));td(tr,c.ticket);td(tr,c.origin);td(tr,c.issuer_email);td(tr,c.status,c.status);
  td(tr,c.redeemed_at?(t(c.redeemed_at)+' '+(c.redeemed_label||'')+' '+(c.redeemed_device||'').slice(0,8)):'');
  const a=td(tr,'');if(c.status==='active'||c.status==='redeemed'){const b=document.createElement('button');b.className='secondary';b.textContent='Revoke';b.style.marginTop='0';
   b.onclick=async()=>{if(!confirm('Revoke this code?'))return;await fetch('/admin/api/codes/'+c.code_id+'/revoke',{method:'POST',headers:H,body:'{}'});load();};a.appendChild(b);}
  tb.appendChild(tr);}
}
document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const err=document.getElementById('err');err.textContent='';
 const body={ticket:ticket.value,url:url.value,reason:reason.value,grantTtlSeconds:+ttl.value};
 const r=await fetch('/admin/api/codes',{method:'POST',headers:H,body:JSON.stringify(body)});const j=await r.json();
 if(!j.ok){err.textContent=j.message||'Failed';return;}
 document.getElementById('code').textContent=j.code;document.getElementById('oorigin').textContent=j.origin;
 document.getElementById('oticket').textContent=j.ticket;document.getElementById('oexp').textContent=t(j.expiresAt);
 document.getElementById('out').hidden=false;load();};
document.getElementById('refresh').onclick=load;me();load();
</script></body></html>`;

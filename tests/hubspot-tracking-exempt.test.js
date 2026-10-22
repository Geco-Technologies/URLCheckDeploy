// node tests/hubspot-tracking-exempt.test.js [extDir]
// Extracts the real detector code from scripts/content.js and scripts/content-early.js
// (no copies) and checks the HubSpot exemption + that other rules are unchanged.
const fs=require('fs'),path=require('path'),vm=require('vm');
const dir=process.argv[2]||path.join(__dirname,'..');
const src=fs.readFileSync(path.join(dir,'scripts/content.js'),'utf8');
const a=src.indexOf('  const GENERIC_SSO_QUERY_PARAMS'), endMark='    return { score, reasons };\n  }\n';
const b=src.indexOf(endMark,a)+endMark.length;
if(a<0||b<endMark.length) throw new Error('could not extract content.js detector');
const ctx={URL,console}; vm.createContext(ctx);
vm.runInContext(src.slice(a,b)+'\nthis.has=hasSpearPhishingTrackingId;this.score=scoreGenericPhishingUrl;',ctx);
const early=fs.readFileSync(path.join(dir,'scripts/content-early.js'),'utf8');
const ea=early.indexOf('  const SSO_QUERY_PARAMS'), eb=early.indexOf('  // Only activate on URLs');
const ectx={URL,window:{location:{href:''}}}; vm.createContext(ectx);
vm.runInContext(early.slice(ea,eb)+'\nthis.has=hasSpearPhishingTrackingId;this.quick=quickUrlScore;',ectx);
const B64='p2ANqtz-8xYz3kQwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcdEFGH_ij';
const LONG='CJbjp7Snv90lH5CyQwErTyUiOpAsDfGhJkLzXcVbNm12345';
const DIG='1234567890123456789012345678901234567890123';
const cases=[
 // [desc, search, expectFlag]
 ['Laura: utm + _hsenc (p2ANqtz) only','?utm_medium=email&_hsenc='+B64+'&utm_source=hs',false],
 ['real-world _hsenc + _hsmi numeric','?_hsenc='+B64+'&_hsmi=330925143',false],
 ['_hsenc WITHOUT p2ANqtz prefix flagged','?_hsenc='+LONG,true],
 ['_hsenc lowercase prefix p2anqtz flagged','?_hsenc=p2anqtz-'+LONG,true],
 ['_hsmi long numeric exempt','?_hsmi='+DIG,false],
 ['_hsmi long base64 flagged','?_hsmi='+LONG,true],
 ['__hstc/__hssc/__hsfp numeric exempt','?__hstc='+DIG+'&__hssc='+DIG+'&__hsfp='+DIG,false],
 ['__hstc long base64 flagged','?__hstc='+LONG,true],
 ['__hsfp long base64 flagged','?__hsfp='+LONG,true],
 ['uppercase _HSENC name w/ p2ANqtz exempt','?_HSENC='+B64,false],
 ['hsCtaTracking (name >8 chars never matched)','?hsCtaTracking='+LONG,false],
 ['_hsenc plus attacker id= still flagged','?_hsenc='+B64+'&id='+LONG,true],
 ['attacker id= before _hsenc still flagged','?id='+LONG+'&_hsenc='+B64,true],
 ['lookalike name x_hsenc flagged','?x_hsenc='+B64,true],
 ['lookalike name hsenc (no _) flagged','?hsenc='+B64,true],
 ['lookalike _hsencx flagged','?_hsencx='+B64,true],
 ['checkmaster _tok still flagged','?_tok='+LONG,true],
 ['spear id= still flagged','?id='+LONG,true],
 ['SSO code= still exempt','?code='+LONG,false],
 ['short value not flagged','?id=abc',false],
];
let fail=0;
for(const [d,s,exp] of cases){
  const r1=ctx.has(s), r2=ectx.has(s);
  const ok=r1===exp&&r2===exp; if(!ok) fail++;
  console.log((ok?'PASS ':'FAIL ')+d+'  content='+r1+' early='+r2+' expect='+exp);
}
// Full URL scoring: rest of URL still judged
const sc=[
 ['phish host w/ fake _hsenc (no prefix) keeps tracking points','https://tpio-mail-internalserver.zenviq.vu/?_hsenc='+LONG,(r)=>r.reasons.some(x=>/base64url/.test(x))&&r.score>=90],
 ['Laura URL total score 0','https://app.thecosechouse.co.uk/firstorder.php?utm_medium=email&_hsenc='+B64,(r)=>r.score===0],
 ['phish host w/ real-shape _hsenc keeps keyword/hyphen/TLD points','https://tpio-mail-internalserver.zenviq.vu/?_hsenc='+B64,(r)=>r.score>=40&&!r.reasons.some(x=>/base64url/.test(x))],
 ['phish host w/ id= unchanged (>=90 incl tracking)','https://tpio-mail-internalserver.zenviq.vu/?id='+LONG,(r)=>r.reasons.some(x=>/base64url/.test(x))&&r.score>=90],
 ['phish host _hsenc + id= still gets tracking points','https://tpio-mail-internalserver.zenviq.vu/?_hsenc='+B64+'&id='+LONG,(r)=>r.reasons.some(x=>/base64url/.test(x))],
];
for(const [d,u,f] of sc){const r=ctx.score(u);const ok=f(r);if(!ok)fail++;console.log((ok?'PASS ':'FAIL ')+d+'  score='+r.score+' reasons='+JSON.stringify(r.reasons));}
console.log('failures',fail); process.exit(fail?1:0);

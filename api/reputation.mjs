// BYOK relay: accepts only a SHA-256; never accepts or uploads file bytes.
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');
 if(req.method!=='POST')return res.status(405).json({error:'method'});
 const origin=req.headers.origin;try{if(origin&&new URL(origin).host!==req.headers.host)return res.status(403).json({error:'origin'})}catch{return res.status(403).json({error:'origin'})}
 let body=req.body;try{if(typeof body==='string')body=JSON.parse(body)}catch{return res.status(400).json({error:'json'})}
 if(!body||Object.keys(body).some(k=>!['sha256'].includes(k))||!/^[a-f0-9]{64}$/.test(body.sha256||''))return res.status(400).json({error:'sha256_only'});
 const key=req.headers['x-vt-key'];if(typeof key!=='string'||!key.trim()||key.length>512)return res.status(401).json({error:'key_required'});
 try{const r=await fetch('https://www.virustotal.com/api/v3/files/'+body.sha256,{headers:{'x-apikey':key},signal:AbortSignal.timeout(12000)});
 if(r.status===404)return res.status(200).json({provider:'VirusTotal',status:'unknown',sha256:body.sha256,checkedAt:Date.now()});
 if(r.status===429)return res.status(429).json({error:'quota'});if(!r.ok)return res.status(r.status===401||r.status===403?401:502).json({error:'provider'});
 const data=await r.json(),a=data.data?.attributes,s=a?.last_analysis_stats;if(!s)return res.status(502).json({error:'invalid_report'});
 return res.status(200).json({provider:'VirusTotal',status:s.malicious>0||s.suspicious>0?'detections':'no_detections',sha256:body.sha256,checkedAt:Date.now(),analysisAt:a.last_analysis_date||null,stats:{malicious:s.malicious||0,suspicious:s.suspicious||0,undetected:s.undetected||0,harmless:s.harmless||0}});
 }catch{return res.status(502).json({error:'unavailable'})}
}

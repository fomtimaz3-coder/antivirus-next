// Hash lookup only; never accepts file data or arbitrary upstream URLs.
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');if(req.method!=='POST')return res.status(405).json({error:'method'});
 try{if(req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host)return res.status(403).json({error:'origin'})}catch{return res.status(403).json({error:'origin'})}
 let body=req.body;try{if(typeof body==='string')body=JSON.parse(body)}catch{return res.status(400).json({error:'json'})}
 if(!body||Object.keys(body).some(k=>!['sha256','provider'].includes(k))||!/^[a-f0-9]{64}$/.test(body.sha256||''))return res.status(400).json({error:'sha256_only'});
 const provider=body.provider||'VirusTotal';if(!['VirusTotal','MalwareBazaar'].includes(provider))return res.status(400).json({error:'provider'});
 const key=req.headers[provider==='VirusTotal'?'x-vt-key':'x-abuse-key'];if(typeof key!=='string'||!key.trim()||key.length>512)return res.status(401).json({error:'key_required'});
 const common={provider,sha256:body.sha256,checkedAt:Date.now()};
 try{const r=provider==='VirusTotal'?await fetch('https://www.virustotal.com/api/v3/files/'+body.sha256,{headers:{'x-apikey':key},signal:AbortSignal.timeout(12000)}):await fetch('https://mb-api.abuse.ch/api/v1/',{method:'POST',headers:{'Auth-Key':key,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({query:'get_info',hash:body.sha256}).toString(),signal:AbortSignal.timeout(12000)});
 if(r.status===404&&provider==='VirusTotal')return res.status(200).json({...common,status:'unknown'});if(r.status===429)return res.status(429).json({error:'quota'});if(!r.ok)return res.status([401,403].includes(r.status)?r.status:502).json({error:r.status===401?'authentication':r.status===403?'forbidden':'provider'});
 const data=await r.json();if(provider==='MalwareBazaar'){if(data.query_status==='hash_not_found')return res.status(200).json({...common,status:'unknown'});if(data.query_status!=='ok'||!Array.isArray(data.data))return res.status(502).json({error:'invalid_report'});const item=data.data.find(x=>x.sha256_hash===body.sha256);if(!item)return res.status(502).json({error:'hash_mismatch'});return res.status(200).json({...common,status:'detections',signature:typeof item.signature==='string'?item.signature.slice(0,200):null,firstSeen:item.first_seen||null})}
 if(data.data?.id!==body.sha256)return res.status(502).json({error:'hash_mismatch'});const a=data.data?.attributes,s=a?.last_analysis_stats;if(!s)return res.status(502).json({error:'invalid_report'});const stats={};for(const k of ['malicious','suspicious','undetected','harmless']){if(!Number.isInteger(s[k])||s[k]<0)return res.status(502).json({error:'invalid_stats'});stats[k]=s[k]}
 return res.status(200).json({...common,status:stats.malicious||stats.suspicious?'detections':Object.values(stats).some(x=>x>0)?'no_detections':'unknown',analysisAt:a.last_analysis_date||null,stats});
 }catch{return res.status(502).json({error:'unavailable'})}
}

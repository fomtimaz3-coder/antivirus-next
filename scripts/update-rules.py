"""Fetch the public Malpedia auto feed only. No private token or samples."""
import io,json,hashlib,zipfile,urllib.request,pathlib,re,datetime,sys
root=pathlib.Path(__file__).resolve().parents[1];rules=root/'rules'
url='https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip'
if len(sys.argv)>1: data=pathlib.Path(sys.argv[1]).read_bytes()
else:
 with urllib.request.urlopen(url,timeout=60) as r: data=r.read(20*1024*1024+1)
if len(data)>20*1024*1024: raise ValueError('Feed exceeds download limit')
z=zipfile.ZipFile(io.BytesIO(data));infos=z.infolist()
if len(infos)>5000 or sum(x.file_size for x in infos)>40*1024*1024: raise ValueError('Feed exceeds expanded limit')
accepted={};skipped=[]
for entry in sorted(infos,key=lambda x:x.filename):
 name=entry.filename;platform=name.split('.')[0]
 if platform not in ['win','osx','elf'] or not re.fullmatch(r'[a-zA-Z0-9_.-]+\.yar',name):skipped.append(name);continue
 text=z.read(entry).decode('utf-8')
 if entry.file_size>512*1024 or not re.search(r'malpedia_license\s*=\s*"CC BY-SA 4.0"',text) or not re.search(r'malpedia_sharing\s*=\s*"TLP:(WHITE|CLEAR)"',text) or re.search(r'^\s*(import|include)\s',text,re.M):skipped.append(name);continue
 accepted.setdefault(platform,[]).append((name,text))
if not sum(map(len,accepted.values())):raise ValueError('No eligible public rules')
shards=[];payloads={};provenance=[]
for platform,entries in sorted(accepted.items()):
 chunks=[];chunk='';count=0
 for name,text in entries:
  if len((chunk+text).encode())>512*1024 and chunk: chunks.append((chunk,count));chunk='';count=0
  chunk+='\n'+text;count+=1;provenance.append({'name':name,'sha256':hashlib.sha256(text.encode()).hexdigest()})
 if chunk:chunks.append((chunk,count))
 for i,(text,count) in enumerate(chunks):
  path=f'rules/malpedia-{platform}-{i:03d}.yar';content=text.encode();payloads[path]=content;shards.append({'path':path,'sha256':hashlib.sha256(content).hexdigest(),'platform':platform,'count':count})
core=[]
for name in ['MALW_Eicar.yar','RANSOM_MS17-010_Wannacrypt.yar','RANSOM_Petya.yar']:
 b=(rules/name).read_bytes();core.append({'path':'rules/'+name,'sha256':hashlib.sha256(b).hexdigest()})
identity=hashlib.sha256(json.dumps(core+shards,sort_keys=True).encode()).hexdigest()[:12]
old=json.loads((rules/'manifest.json').read_text());now=datetime.datetime.now(datetime.timezone.utc).isoformat();version='mp-'+identity
manifest={'schema':2,'version':version,'published':old.get('published',now) if old.get('version')==version else now,'engine':'YARA 4.5.8','ruleCount':8+sum(s['count'] for s in shards),'description':f"8 стартовых правил + {sum(s['count'] for s in shards)} публичных правил Malpedia для Windows, ELF и macOS. Автогенерация по распакованным образцам; покрытие Android DEX не расширено.",'files':core,'shards':shards,'feed':url,'license':'Malpedia CC BY-SA 4.0; starter GPL-2.0','skippedCount':len(skipped)}
for p in rules.glob('malpedia-*.yar'):
 if str(p.relative_to(root)) not in payloads:p.unlink()
for path,data in payloads.items():(root/path).write_bytes(data)
(rules/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
(rules/'malpedia-provenance.json').write_text(json.dumps({'feed':url,'license':'CC BY-SA 4.0','licenseUrl':'https://creativecommons.org/licenses/by-sa/4.0/','modifications':'None to rule contents; files concatenated into platform shards.','files':provenance,'skipped':skipped},indent=2)+'\n')
print(json.dumps({'version':version,'rules':manifest['ruleCount'],'shards':len(shards),'skipped':len(skipped)}))

#!/usr/bin/env python3
"""Deploy current auth source using credentials supplied over SSH stdin."""
import hashlib,json,os,pathlib,shutil,ssl,subprocess,sys,time,urllib.request,http.cookiejar
P=pathlib.Path(__file__).resolve().parent
VERSION='2026.11.25.1'
NAME='network-auth-service'
IMAGE='chateauneuf-auth:'+VERSION
os.umask(0o077)
def run(*args):
 return subprocess.check_output(args,text=True,stderr=subprocess.PIPE).strip()
def inspect(name):return json.loads(run('docker','inspect',name))[0]
def request(op,url,data=None,headers=None):
 req=urllib.request.Request(url,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json',**(headers or {})})
 with op.open(req,timeout=20) as res:return json.load(res)
credentials=json.load(sys.stdin)
assert set(credentials)=={'OMADA_USERNAME','OMADA_PASSWORD'} and all(credentials.values())
assert all('\n' not in v and '\r' not in v for v in credentials.values())
manifest=json.loads((P/'source.json').read_text(encoding='utf-8-sig'))
assert hashlib.sha256((P/'source.tar.gz').read_bytes()).hexdigest()==manifest['sha256']
current=inspect(NAME)
env=dict(x.split('=',1) for x in current['Config']['Env'] if '=' in x);env.update(credentials)
op=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
base=env['OMADA_BASE_URL'].rstrip('/')
login=request(op,base+'/'+env['OMADA_CONTROLLER_ID']+'/api/v2/hotspot/login',{'name':env['OMADA_USERNAME'],'password':env['OMADA_PASSWORD']})
assert login.get('errorCode')==0 and login.get('result',{}).get('token'),'Hotspot login rejected'
clients=request(op,base+'/'+env['OMADA_CONTROLLER_ID']+'/api/v2/hotspot/sites/'+env['OMADA_SITE_ID']+'/clients?currentPage=1&currentPageSize=1',headers={'Csrf-Token':login['result']['token']})
assert clients.get('errorCode')==0,'Hotspot client listing rejected'
print('Hotspot login and client-list permissions passed',flush=True)
(P/'source').mkdir(mode=0o700,exist_ok=True)
subprocess.run(['tar','-xzf',str(P/'source.tar.gz'),'-C',str(P/'source')],check=True)
subprocess.run(['docker','build','--build-arg','APP_VERSION='+VERSION,'--build-arg','GIT_COMMIT='+manifest['commit'],'-t',IMAGE,str(P/'source')],check=True)
assert inspect(IMAGE)['Config']['Labels']['org.opencontainers.image.revision']==manifest['commit']
# Preserve the runtime identity and volume; never reset application records.
networks=current['NetworkSettings']['Networks'];assert len(networks)==1
network,endpoint=next(iter(networks.items()));address=endpoint['IPAddress']
assert network==current['HostConfig']['NetworkMode']
mounts=current['Mounts'];assert all(m['Type']=='bind' for m in mounts)
users_mount=next(m for m in mounts if m['Destination']=='/app/data')
users_path=pathlib.Path(users_mount['Source'])/'users.json'
backup=P/'before-deploy';backup.mkdir(mode=0o700)
(backup/'container.json').write_text(json.dumps(current))
other={n:inspect(n)['Id'] for n in run('docker','ps','--format','{{.Names}}').splitlines() if n!=NAME}
http=urllib.request.build_opener()
def accounts():return request(http,'http://127.0.0.1:8081/api/internet-accounts')
old_ids={x['id'] for x in accounts()}
env_file=P/'auth.env';env_file.write_text('\n'.join(k+'='+v for k,v in env.items())+'\n');env_file.chmod(0o600)
old_name=NAME+'-before-'+VERSION
stopped=renamed=detached=False
try:
 run('docker','stop',NAME);stopped=True
 shutil.copy2(users_path,backup/'users.json')
 run('docker','rename',NAME,old_name);renamed=True
 run('docker','network','disconnect',network,old_name);detached=True
 cmd=['docker','create','--name',NAME,'--restart',current['HostConfig']['RestartPolicy']['Name'],'--env-file',str(env_file),'--network',network,'--ip',address]
 for alias in endpoint.get('Aliases') or []:
  if alias not in (NAME,current['Id'][:12]):cmd+=['--network-alias',alias]
 for m in mounts:cmd+=['--mount','type=bind,src='+m['Source']+',dst='+m['Destination']+('' if m['RW'] else ',readonly')]
 for port,bindings in (current['HostConfig']['PortBindings'] or {}).items():
  for b in bindings or []:cmd+=['-p',(b['HostIp']+':' if b['HostIp'] else '')+b['HostPort']+':'+port]
 cmd+=[IMAGE];run(*cmd);run('docker','start',NAME)
 for attempt in range(30):
  try:
   assert request(http,'http://192.168.10.100:8080/health')['status']=='UP'
   assert old_ids=={x['id'] for x in accounts()}
   break
  except Exception:
   if attempt==29:raise
   time.sleep(2)
 for n,id in other.items():assert inspect(n)['Id']==id and inspect(n)['State']['Running'],n+' changed'
 run('docker','exec',NAME,'wget','-q','-O','/dev/null',env['RESIDENTS_API_URL'])
 report={'version':VERSION,'status':'passed','commit':manifest['commit'],'accounts_preserved':len(old_ids),'other_services_unchanged':list(other),'hotspot_login':'passed','hotspot_client_listing':'passed','backup':str(backup),'image_id':inspect(IMAGE)['Id']}
 (P/'deployment-report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
except Exception:
 if renamed:
  if subprocess.run(['docker','inspect',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:run('docker','rm','-f',NAME)
  if detached:run('docker','network','connect','--ip',address,network,old_name)
  run('docker','rename',old_name,NAME)
 if stopped:run('docker','start',NAME)
 print('Deployment failed; previous container restarted without restoring account data.',flush=True)
 raise

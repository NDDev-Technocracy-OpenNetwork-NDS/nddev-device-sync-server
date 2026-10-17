"""Actual signed HTTP and PostgreSQL atomic log acceptance; OpenSSL is independent
of the production signature parser/provider. Only this disposable fixture is used."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid
from vault_acceptance import check_vault
from sync_capacity_acceptance import check_capacity

def b64(value): return base64.urlsafe_b64encode(value).decode().rstrip('=')

def check_sync(request, token, restart, directory, sql, origin, observability_configured=False):
    parsed = urlsplit(origin)
    assert parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost') and parsed.port
    directory=Path(directory)/'sync';directory.mkdir(mode=0o700)
    sensitive=[]
    def openssl(*args):
        return subprocess.run(['openssl',*map(str,args)],check=True,capture_output=True,timeout=5).stdout
    def enroll(index):
        key=directory/f'device-{index}.pem'
        openssl('genpkey','-algorithm','ED25519','-out',key);key.chmod(0o600)
        sensitive.extend(key.read_text().splitlines()[1:-1])
        public=openssl('pkey','-in',key,'-pubout','-outform','DER')[12:]
        status,challenge=request('/v2/devices/challenges',{'platform':'linux','display_name':f'Sync acceptance {index}','public_key':b64(public)},token=token)
        assert status==201
        content=directory/f'proof-{index}.bin';content.write_bytes(b'NDS-ENROLLMENT-V2\0'+base64.urlsafe_b64decode(challenge['challenge']+'='))
        status,device=request('/v2/devices/enrollments',{'challenge_id':challenge['challenge_id'],'signature':b64(openssl('pkeyutl','-sign','-inkey',key,'-rawin','-in',content))},token=token)
        assert status==201
        return key,device['device_id']
    http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def send(key,device,path,body=None,nonce=None,signature_body=None,target=None,include_headers=False):
        method='GET' if body is None else 'POST';body=b'' if body is None else body
        digest='sha-256=:'+base64.b64encode(hashlib.sha256(body if signature_body is None else signature_body).digest()).decode()+':'
        now=int(time.time());nonce=nonce or b64(secrets.token_bytes(24))
        params=f'("@method" "@target-uri" "content-digest");created={now};expires={now+60};nonce="{nonce}";alg="ed25519";keyid="{device}"'
        base=f'"@method": {method}\n"@target-uri": {target or origin+path}\n"content-digest": {digest}\n"@signature-params": {params}'
        # Unique files are required because concurrent requests sign independently.
        content=directory/(uuid.uuid4().hex+'.bin');content.write_bytes(base.encode())
        try:signature=openssl('pkeyutl','-sign','-inkey',key,'-rawin','-in',content)
        finally:content.unlink()
        headers={'Authorization':'Bearer '+token,'Signature-Input':'nds='+params,'Signature':'nds=:'+base64.b64encode(signature).decode()+':','Content-Digest':digest,'Content-Type':'application/json'}
        req=urllib.request.Request(origin+path,data=body if method=='POST' else None,headers=headers,method=method)
        try:response=http.open(req,timeout=8)
        except urllib.error.HTTPError as error:response=error
        with response:
            raw=response.read(65537);assert len(raw)<=65536
            assert response.headers['Cache-Control']=='no-store'
            if include_headers:
                return response.status,raw,dict(response.headers)
            return response.status,raw
    def operation(device,revision=0,operation_id=None):
        id=operation_id or uuid.uuid4().hex
        return {'schema_version':2,'operation_id':id,'device_id':device,'entity_type':'vault_record','entity_id':'acceptance-record','base_revision':revision,'idempotency_key':id,
            'payload':{'algorithm':'aes-256-gcm','key_id':'acceptance-key','nonce':b64(secrets.token_bytes(12)),'ciphertext':b64(secrets.token_bytes(32))}}
    first,id1=enroll(1);second,id2=enroll(2)
    if observability_configured:
        status,raw=send(first,id1,'/v2/observability/status')
        assert status==200 and 'sources' in json.loads(raw), 'configured bootstrap operator lost its pipeline access'
        status,raw=send(first,id1,'/v2/observability/client-policy')
        assert status==200 and json.loads(raw)=={'export_mode':'enabled'}

    value=operation(id1);body=json.dumps(value,separators=(',',':')).encode()
    assert request('/v2/sync/operations',value,token=token)[0]==400
    assert send(first,id1,'/v2/sync/operations',body,signature_body=b'altered')[0]==400
    assert send(first,id1,'/v2/sync/operations',body,target='https://foreign.example/v2/sync/operations')[0]==400
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=list(pool.map(lambda _:send(first,id1,'/v2/sync/operations',body),range(2)))
    assert outcomes[0]==outcomes[1] and outcomes[0][0]==201
    original=outcomes[0]
    assert json.loads(original[1])=={'outcome':'applied','operation_id':value['operation_id'],'revision':1,'server_seq':1}
    assert sql('SELECT count(*) FROM nds_replica_operations').stdout.strip()=='1'
    competing=operation(id2);competing['payload']['key_id']='different-vault-key'
    status,blocked=send(second,id2,'/v2/sync/operations',json.dumps(competing,separators=(',',':')).encode())
    assert status==409 and json.loads(blocked)=={'error':'operation_conflict'}
    assert sql('SELECT root_key_id FROM nds_replica_counters').stdout.strip()=='acceptance-key'
    assert sql('SELECT server_seq FROM nds_replica_counters').stdout.strip()=='1'
    # Same logical JSON with changed exact bytes cannot reuse a receipt.
    assert send(first,id1,'/v2/sync/operations',json.dumps(value,indent=1).encode())[0]==409
    nonce=b64(secrets.token_bytes(24))
    assert send(first,id1,'/v2/sync/operations',body,nonce=nonce)==original
    status,error=send(first,id1,'/v2/sync/operations',body,nonce=nonce)
    assert status==409 and json.loads(error)=={'error':'replayed_nonce'}
    conflict=json.dumps(operation(id2),separators=(',',':')).encode()
    status,result=send(second,id2,'/v2/sync/operations',conflict)
    assert status==409 and json.loads(result)['outcome']=='conflict'
    assert sql('SELECT revision FROM nds_replica_entities').stdout.strip()=='1'
    assert sql('SELECT count(*) FROM nds_replica_operations').stdout.strip()=='2'
    status,raw=send(second,id2,'/v2/sync/operations?after_seq=0&limit=2')
    page=json.loads(raw);assert status==200 and len(page['entries'])==2 and page['next_after_seq']==2 and not page['has_more']
    assert page['entries'][0]['operation']==value and page['entries'][1]['operation']==json.loads(conflict)
    restart()
    assert send(first,id1,'/v2/sync/operations',body)==original
    # A real statement failure rolls back both state and committed sequence.
    update=json.dumps(operation(id1,revision=1),separators=(',',':')).encode()
    sql('REVOKE INSERT ON nds_replica_operations FROM nds_runtime')
    assert send(first,id1,'/v2/sync/operations',update)[0]==503
    assert sql('SELECT revision FROM nds_replica_entities').stdout.strip()=='1'
    assert sql('SELECT server_seq FROM nds_replica_counters').stdout.strip()=='2'
    sql('GRANT INSERT ON nds_replica_operations TO nds_runtime')
    status,result=send(first,id1,'/v2/sync/operations',update)
    assert status==201 and json.loads(result)['server_seq']==3
    # Small records use the requested item budget; large records are bounded by
    # their actual encoded page size. Both limits preserve a contiguous cursor.
    expected=[]
    for index in range(120):
        item=operation(id1);item['entity_id']=f'page-small-{index}'
        status,result=send(first,id1,'/v2/sync/operations',json.dumps(item,separators=(',',':')).encode())
        assert status==201 and json.loads(result)['server_seq']==4+index
        expected.append(item['operation_id'])
    for query in ['after_seq=3', 'after_seq=3&limit=2']:
        status,raw=send(second,id2,'/v2/sync/operations?'+query)
        observed=json.loads(raw)
        assert status==200 and len(observed['entries'])==2
        assert observed['next_after_seq']==5 and observed['has_more']
    status,raw=send(second,id2,'/v2/sync/operations?after_seq=3&limit=100')
    observed=json.loads(raw)
    assert status==200 and len(raw)<=60*1024 and len(observed['entries'])==100
    assert observed['next_after_seq']==103 and observed['has_more']
    assert [entry['operation']['operation_id'] for entry in observed['entries']]==expected[:100]
    status,raw=send(second,id2,'/v2/sync/operations?after_seq=103&limit=100')
    observed=json.loads(raw)
    assert status==200 and len(raw)<=60*1024 and len(observed['entries'])==20
    assert observed['next_after_seq']==123 and not observed['has_more']
    assert [entry['operation']['operation_id'] for entry in observed['entries']]==expected[100:]
    expected=[]
    for index in range(7):
        item=operation(id1);item['entity_id']=f'page-large-{index}'
        item['payload']['ciphertext']=b64(secrets.token_bytes(16000))
        status,result=send(first,id1,'/v2/sync/operations',json.dumps(item,separators=(',',':')).encode())
        assert status==201 and json.loads(result)['server_seq']==124+index
        expected.append(item['operation_id'])
    cursor=123;received=[];reads=0
    while cursor<130:
        status,raw=send(second,id2,f'/v2/sync/operations?after_seq={cursor}&limit=100')
        observed=json.loads(raw);reads+=1
        assert status==200 and len(raw)<=60*1024 and observed['entries']
        assert [entry['result']['server_seq'] for entry in observed['entries']]==list(range(cursor+1,cursor+1+len(observed['entries'])))
        received.extend(entry['operation']['operation_id'] for entry in observed['entries'])
        cursor=observed['next_after_seq']
        assert observed['has_more']==(cursor<130)
    assert received==expected and reads==4
    status,raw=send(second,id2,'/v2/sync/operations?after_seq=130&limit=100')
    assert status==200 and json.loads(raw)=={'entries':[],'next_after_seq':130,'has_more':False}
    for limit in [0,101]:
        assert send(second,id2,f'/v2/sync/operations?after_seq=0&limit={limit}')[0]==400
    check_capacity(send, first, id1, operation, body, original, sql, restart)
    assert request('/v2/devices/'+id1,token=token,method='DELETE')[0]==204
    assert send(first,id1,'/v2/sync/operations',body)[0]==403
    assert send(first,id1,'/v2/sync/operations?after_seq=0')[0]==403
    assert sql('UPDATE nds_replica_operations SET status=201 WHERE false','nds_runtime',check=False).returncode!=0
    assert sql('UPDATE nds_replica_counters SET admission_version=3 WHERE false','nds_runtime',check=False).returncode!=0
    # Explicit cleanup of this fixture's two identities before the independent
    # enrollment capacity suite. Production has no operation/history reset API.
    sql('DELETE FROM nds_replica_base_members; DELETE FROM nds_replica_entities; DELETE FROM nds_replica_operations; DELETE FROM nds_replica_nonces; DELETE FROM nds_replica_counters; DELETE FROM nds_enrollment_challenges; DELETE FROM nds_devices; DELETE FROM nds_auth_limits;')
    sensitive.extend(check_vault(enroll, send, request, token, restart, directory, sql))
    print('Signed sync acceptance passed: independent OpenSSL proofs; atomic duplicate/replay/conflict handling; exact-byte receipts; committed-order item/encoded-byte pages; restart persistence; actual SQL rollback and revocation before replay.')
    return sensitive

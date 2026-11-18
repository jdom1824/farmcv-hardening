"""Admin-only demo entry point. Run one worker, loopback only, behind HTTPS Funnel."""
import hashlib
import asyncio
import hmac
import ipaddress
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
import jwt
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from .main import app, lifespan as api_lifespan
from .config import settings
from .auth import verify_password
from .public_cv import PUBLIC_PATH, PUBLIC_ASSETS
from . import admin_farms
from . import print_card
from .public_home import PUBLIC_PAGES

@asynccontextmanager
async def admin_lifespan(application):
 await run_in_threadpool(admin_farms.initialize_index)
 async with api_lifespan(application):
  tasks=[asyncio.create_task(admin_farms.scan_registrations()),asyncio.create_task(admin_farms.refresh_records())]
  try:
   yield
  finally:
   for task in tasks:task.cancel()
   await asyncio.gather(*tasks,return_exceptions=True)

app.router.lifespan_context=admin_lifespan

COOKIE='__Host-farmcv'
login_attempts_by_client=OrderedDict()
login_in_flight_by_client={}
login_in_flight_total=0
requests_by_client=OrderedDict()
login_state_lock=threading.Lock()
MAX_REQUESTS_PER_MINUTE=600
MAX_LOGIN_FAILURES_PER_MINUTE=10
MAX_CONCURRENT_LOGIN_CHECKS=4
RATE_LIMIT_WINDOW_SECONDS=60
MAX_TRACKED_CLIENTS=4096
MAX_REQUEST_BYTES=11*1024*1024
MAX_LOGIN_BYTES=4096
FARM_ID_PATTERN=r'0x[0-9a-fA-F]{64}'
PHOTO_UPLOAD_PATH=re.compile(r'(?:/admin/farms|/farm-cv)/'+FARM_ID_PATTERN+r'/photos')
PHOTO_UPLOAD_SLOTS=threading.BoundedSemaphore(2)
PUBLIC_API_ROUTES=(
 ('GET',re.compile(r'/health')),
 ('GET',re.compile(r'/networks')),
 ('GET',re.compile(r'/farm-cv/'+FARM_ID_PATTERN+r'/exists')),
 ('GET',re.compile(r'/farm-cv/'+FARM_ID_PATTERN)),
 ('GET',re.compile(r'/farm-cv/'+FARM_ID_PATTERN+r'/transactions')),
 ('GET',re.compile(r'/transactions/'+FARM_ID_PATTERN)),
 ('GET',re.compile(r'/operations/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')),
 ('POST',re.compile(r'/farm-cv/'+FARM_ID_PATTERN+r'/verify')),
 ('POST',re.compile(r'/validation/farm-cv')),
)
# Server-side sessions are deliberately invalidated on restart.
sessions={}
def limited_by_client(buckets, identity, count, seconds):
 now=time.monotonic()
 with login_state_lock:
  bucket=buckets.get(identity)
  if bucket is not None:
   while bucket and bucket[0]<now-seconds: bucket.popleft()
   if len(bucket)>=count:
    buckets.move_to_end(identity)
    return True
   if not bucket:
    del buckets[identity]
    bucket=None
  if bucket is None:
   if len(buckets)>=MAX_TRACKED_CLIENTS:
    buckets.popitem(last=False)
   bucket=deque()
   buckets[identity]=bucket
  bucket.append(now)
  buckets.move_to_end(identity)
  return False

def trusted_proxy_networks():
 raw=getattr(settings,'trusted_proxy_cidrs','')
 if isinstance(raw,str):
  entries=[item.strip() for item in raw.split(',') if item.strip()]
 else:
  entries=list(raw or ())
 try:
  return tuple(ipaddress.ip_network(item,strict=False) for item in entries)
 except (TypeError,ValueError):
  # An invalid/partial trust list must never enable forwarded-header trust.
  return ()

def client_identity(request):
 peer=request.client.host if request.client else ''
 try:
  peer_ip=ipaddress.ip_address(peer)
 except (TypeError,ValueError):
  return 'unknown'
 networks=trusted_proxy_networks()
 if not any(peer_ip.version==net.version and peer_ip in net for net in networks):
  return peer_ip.compressed
 values=request.headers.getlist('x-forwarded-for')
 if not values:
  return peer_ip.compressed
 parts=[part.strip() for value in values for part in value.split(',')]
 if not parts or any(not part for part in parts):
  return peer_ip.compressed
 try:
  forwarded=[ipaddress.ip_address(part) for part in parts]
 except ValueError:
  return peer_ip.compressed
 chain=[*forwarded,peer_ip]
 for hop in reversed(chain):
  if any(hop.version==net.version and hop in net for net in networks):
   continue
  return hop.compressed
 return peer_ip.compressed

def reserve_login_slot(identity):
 global login_in_flight_total
 now=time.monotonic()
 with login_state_lock:
  bucket=login_attempts_by_client.get(identity)
  if bucket is not None:
   while bucket and bucket[0]<now-RATE_LIMIT_WINDOW_SECONDS: bucket.popleft()
   if not bucket:
    del login_attempts_by_client[identity]
    bucket=None
  in_flight=login_in_flight_by_client.get(identity,0)
  if (len(bucket) if bucket else 0)+in_flight>=MAX_LOGIN_FAILURES_PER_MINUTE:
   if identity in login_attempts_by_client:
    login_attempts_by_client.move_to_end(identity)
   return 'client_limit'
  if login_in_flight_total>=MAX_CONCURRENT_LOGIN_CHECKS:
   return 'busy'
  if bucket is not None:
   login_attempts_by_client.move_to_end(identity)
  if bucket is None and len(login_attempts_by_client)>=MAX_TRACKED_CLIENTS:
   login_attempts_by_client.popitem(last=False)
  login_in_flight_by_client[identity]=in_flight+1
  login_in_flight_total+=1
  return None

def finish_login_slot(identity, *, failed=False, successful=False):
 global login_in_flight_total
 with login_state_lock:
  in_flight=login_in_flight_by_client.get(identity,0)
  if in_flight>0:
   login_in_flight_total-=1
   if in_flight>1:
    login_in_flight_by_client[identity]=in_flight-1
   else:
    login_in_flight_by_client.pop(identity,None)
  bucket=login_attempts_by_client.get(identity)
  if failed:
   if bucket is None:
    if len(login_attempts_by_client)>=MAX_TRACKED_CLIENTS:
     login_attempts_by_client.popitem(last=False)
    bucket=deque()
    login_attempts_by_client[identity]=bucket
   bucket.append(time.monotonic())
  elif successful and bucket is not None:
   bucket.clear()
  if bucket is not None:
   if bucket:
    login_attempts_by_client.move_to_end(identity)
   else:
    login_attempts_by_client.pop(identity,None)

def content_length_exceeds(request, maximum):
 try:
  return int(request.headers.get('content-length','0'))>maximum
 except ValueError:
  return False

def is_public_api_request(request):
 return any(method==request.method and pattern.fullmatch(request.url.path) for method,pattern in PUBLIC_API_ROUTES)

async def bounded_body(request, maximum):
 if content_length_exceeds(request,maximum):return None
 data=bytearray()
 async for chunk in request.stream():
  if len(data)+len(chunk)>maximum:return None
  data.extend(chunk)
 request._body=bytes(data)
 return request._body

@app.middleware('http')
async def protect(request:Request, call_next):
 path=request.url.path
 async def dispatch():
  identity=client_identity(request)
  if limited_by_client(requests_by_client,identity,MAX_REQUESTS_PER_MINUTE,RATE_LIMIT_WINDOW_SECONDS):return JSONResponse({'detail':'rate limit'},429,headers={'Retry-After':'60'})
  if request.method=='GET' and (path in PUBLIC_PAGES or path=='/admin' or PUBLIC_PATH.fullmatch(path) or path in PUBLIC_ASSETS):
   if content_length_exceeds(request,MAX_REQUEST_BYTES):return JSONResponse({'detail':'request too large'},413)
   return await call_next(request)
  if is_public_api_request(request):
   if content_length_exceeds(request,MAX_REQUEST_BYTES):return JSONResponse({'detail':'request too large'},413)
   if request.method=='POST' and await bounded_body(request,MAX_REQUEST_BYTES) is None:return JSONResponse({'detail':'request too large'},413)
   return await call_next(request)
  if path in {'/session','/auth/login'}:
   if request.method!='POST':return JSONResponse({'detail':'method not allowed'},405)
   origin=request.headers.get('origin')
   if origin and origin!='https://'+request.headers.get('host',''):return JSONResponse({'detail':'origin rejected'},403)
   data=await bounded_body(request,MAX_LOGIN_BYTES)
   if data is None:return JSONResponse({'detail':'login too large'},413)
   try:
    body=await request.json();user=body['username'];password=body['password']
    if not isinstance(user,str) or not isinstance(password,str):raise ValueError()
   except Exception:return JSONResponse({'detail':'invalid request'},400)
   reservation_error=reserve_login_slot(identity)
   if reservation_error:
    retry_after='1' if reservation_error=='busy' else '60'
    detail='login verification capacity reached' if reservation_error=='busy' else 'too many login attempts'
    return JSONResponse({'detail':detail},429,headers={'Retry-After':retry_after})
   settled=False
   try:
    valid=await run_in_threadpool(verify_password,password,settings.admin_password_hash)
    if not valid or not hmac.compare_digest(user,settings.admin_username):
     finish_login_slot(identity,failed=True);settled=True
     return JSONResponse({'detail':'invalid credentials'},401)
    # A valid login resets only a sub-threshold failure window.
    finish_login_slot(identity,successful=True);settled=True
    now=int(time.time());sid=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
    for key in list(sessions):
     if sessions[key]['exp']<=now:del sessions[key]
    # One administrator and one active session; signing in revokes the previous session.
    sessions.clear();sessions[sid]={'exp':now+900,'csrf':csrf}
    token=jwt.encode({'sub':user,'iat':now,'exp':now+900,'sid':sid},settings.jwt_secret,algorithm='HS256')
    response=JSONResponse({'access_token':token,'token_type':'bearer','expires_in':900,'csrf':csrf})
    response.set_cookie(COOKIE,token,max_age=900,secure=True,httponly=True,samesite='strict',path='/')
    return response
   finally:
    if not settled:finish_login_slot(identity)
  authorization=request.headers.get('authorization','')
  is_bearer=authorization.startswith('Bearer ')
  token=authorization[7:] if is_bearer else request.cookies.get(COOKIE,'')
  try:
   claims=jwt.decode(token,settings.jwt_secret,algorithms=['HS256'],options={'require':['exp','iat','sub','sid']})
   session=sessions.get(claims['sid'])
   if claims['sub']!=settings.admin_username or not session or session['exp']<=time.time():raise ValueError()
  except (jwt.PyJWTError,ValueError,TypeError):return JSONResponse({'detail':'authentication required'},401)
  if not is_bearer and request.method not in {'GET','HEAD','OPTIONS'}:
   if not hmac.compare_digest(request.headers.get('x-csrf-token',''),session['csrf']):return JSONResponse({'detail':'CSRF check failed'},403)
  if path=='/session/logout' and request.method=='POST':
   sessions.pop(claims['sid'],None)
   response=JSONResponse({'status':'signed out'});response.delete_cookie(COOKIE,secure=True,httponly=True,samesite='strict',path='/');return response
  # Reuse the original route-level JWT protection for all writes.
  request.scope['headers']=[(k,v) for k,v in request.scope['headers'] if k.lower()!=b'authorization']+[(b'authorization',('Bearer '+token).encode())]
  photo_upload=request.method=='POST' and PHOTO_UPLOAD_PATH.fullmatch(path)
  if photo_upload and not PHOTO_UPLOAD_SLOTS.acquire(blocking=False):
   return JSONResponse({'detail':'photo upload capacity reached'},429,headers={'Retry-After':'1'})
  try:
   if content_length_exceeds(request,MAX_REQUEST_BYTES):return JSONResponse({'detail':'request too large'},413)
   if await bounded_body(request,MAX_REQUEST_BYTES) is None:return JSONResponse({'detail':'request too large'},413)
   return await call_next(request)
  finally:
   if photo_upload:PHOTO_UPLOAD_SLOTS.release()
 response=await dispatch()
 response.headers['Cache-Control']='no-store'
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Referrer-Policy']='no-referrer'
 response.headers['Strict-Transport-Security']='max-age=31536000'
 if path=='/admin':
  response.headers['Content-Security-Policy']="default-src 'none'; img-src data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
 elif path in PUBLIC_PAGES:
  response.headers['Content-Security-Policy']="default-src 'none'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
 elif path.startswith('/fincas/'):
  response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
  response.headers['Content-Security-Policy']="default-src 'none'; img-src 'self' data: https://tile.openstreetmap.org; script-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
 return response

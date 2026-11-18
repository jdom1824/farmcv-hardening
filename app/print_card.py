"""Authenticated, printable A6 card linking to the consented public CV."""
import base64
import io
import re
from html import escape
from pathlib import Path
from fastapi import Depends
from fastapi.responses import HTMLResponse
from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool
from .main import app
from .auth import require_admin
from .models import Bytes32
from .public_cv import published

def build_card(cv, farm_id, base_url):
    import qrcode
    url=base_url.rstrip('/')+'/fincas/'+farm_id.lower()
    qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=10,border=4)
    qr.add_data(url);qr.make(fit=True)
    out=io.BytesIO();qr.make_image(fill_color='black',back_color='white').save(out,format='PNG')
    logo=re.search(r'<img class="logo" src="([^"]+)"',Path(__file__).with_name('public_cv.html').read_text())[1]
    name=escape(str(cv.get('identification',{}).get('farmName','Finca de cacao'))[:150])
    location=cv.get('location',{})
    place=escape(', '.join(str(location.get(k,''))[:100] for k in ['municipality','department'] if location.get(k)))
    template=Path(__file__).with_name('print_card.html').read_text()
    template=template.replace('</style>', '</style><link rel="stylesheet" href="/assets/orika-palette.css">', 1)
    values={'NAME':name,'LOCATION':place,'LOGO':logo,'QR':'data:image/png;base64,'+base64.b64encode(out.getvalue()).decode(),'URL':escape(url,quote=True),'ID':farm_id.lower()}
    return re.sub(r'\{\{([A-Z]+)\}\}',lambda m:values[m[1]],template)

@app.get('/admin/farms/{farm_id}/card',response_class=HTMLResponse)
async def print_card(farm_id:Bytes32,_:str=Depends(require_admin)):
    if not settings.public_base_url:
        raise HTTPException(status_code=503, detail='Public base URL is not configured')
    cv,_=await published(farm_id)
    html=await run_in_threadpool(build_card,cv,farm_id,settings.public_base_url)
    return HTMLResponse(html,headers={'Content-Security-Policy':"default-src 'none'; img-src data:; style-src 'self' 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"})

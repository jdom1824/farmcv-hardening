'use strict';
(() => {
 const button=document.getElementById('verify-button');
 if(!button)return;
 const message=document.getElementById('verify-message');
 const results=document.getElementById('verify-results');
 const evidence=document.getElementById('verify-evidence');
 button.addEventListener('click',async()=>{
  button.disabled=true;button.setAttribute('aria-busy','true');
  message.className='verification-message running';
  message.textContent='Consultando el contrato y recalculando los hashes del CV, el polígono y las fotografías…';
  results.replaceChildren();evidence.textContent='';
  const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),30000);
  try{
   const response=await fetch(location.pathname.replace(/\/$/,'')+'/verificar',{signal:controller.signal,cache:'no-store'});
   if(!response.ok)throw Error('No fue posible completar la comprobación. El servicio puede estar temporalmente no disponible.');
   const data=await response.json();
   message.className='verification-message '+(data.verified?'success':'failed');
   message.textContent=data.verified?'Integridad técnica verificada · '+data.checks.length+' comprobaciones correctas':'Verificación con incidencias · revisa los resultados';
   for(const check of data.checks){
    const row=document.createElement('li');row.className=check.passed?'check-pass':'check-fail';
    const icon=document.createElement('span');icon.className='check-icon';icon.textContent=check.passed?'✓':'!';icon.setAttribute('aria-hidden','true');
    const text=document.createElement('div');const title=document.createElement('strong');title.textContent=check.label+' · '+(check.passed?'Correcto':'Incidencia');
    const detail=document.createElement('p');detail.textContent=check.detail;text.append(title,detail);row.append(icon,text);results.append(row);
   }
   evidence.textContent='Verificado: '+new Date(data.checkedAt).toLocaleString('es-CO')+' · '+data.durationMs+' ms\nRed: '+data.network+' · Chain ID: '+data.chainId+' · Versión: '+data.version+'\nContrato: '+data.contract+'\n'+data.scope;
  }catch(error){
   message.className='verification-message failed';message.textContent=error.name==='AbortError'?'La comprobación excedió el tiempo de espera. No se ha verificado el registro.':error.message;
  }finally{clearTimeout(timeout);button.disabled=false;button.removeAttribute('aria-busy');const label=button.querySelector('.verify-label');if(label)label.textContent='Volver a verificar';else button.textContent='Volver a verificar certificados blockchain';}
 });
})();

(function () {
  'use strict';
  const root = document.documentElement;
  const seasons = {
    spring:{emoji:'🌸',label:'Весна',code:'SPRING MODE',style:'Свежий и лёгкий',mood:'Время цветения'},
    summer:{emoji:'☀️',label:'Лето',code:'SUMMER MODE',style:'Яркий и солнечный',mood:'Тёплое сияние'},
    autumn:{emoji:'🍂',label:'Осень',code:'AUTUMN MODE',style:'Тёплый и уютный',mood:'Золотой свет'},
    winter:{emoji:'❄️',label:'Зима',code:'WINTER MODE',style:'Спокойный и чистый',mood:'Морозное сияние'}
  };
  const modal=document.getElementById('admin-modal');
  const loginView=document.getElementById('admin-login-view');
  const panelView=document.getElementById('admin-panel-view');
  const loginForm=document.getElementById('admin-login-form');
  const loginMessage=document.getElementById('admin-login-message');
  const panelMessage=document.getElementById('admin-message');
  const passwordField=document.getElementById('admin-password');
  let currentSeason=root.dataset.season||'autumn';
  let effectKey='';

  function message(el,text,error){if(!el)return;el.textContent=text||'';el.classList.toggle('error',Boolean(error));}
  let weatherFrame=0, weatherCleanup=null;
  function makeWeather(season){
    if(weatherCleanup){weatherCleanup();weatherCleanup=null;}
    const layer=document.getElementById('weather-layer'); if(!layer)return;
    if(weatherFrame)cancelAnimationFrame(weatherFrame);
    weatherFrame=0;
    layer.replaceChildren();
    if(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches)return;
    const canvas=document.createElement('canvas'); canvas.className='weather-canvas'; canvas.setAttribute('aria-hidden','true'); layer.append(canvas);
    const ctx=canvas.getContext('2d',{alpha:true}); if(!ctx)return;
    const particles=[], settled=[], cell=9, mobile=matchMedia('(max-width:640px)').matches;
    const cap=mobile?26:46, rate=mobile?1.65:2.35;
    let w=0,h=0,dpr=1,pile=[],last=0,spawn=0,time=0;
    function resize(){
      w=innerWidth; h=innerHeight; dpr=Math.min(devicePixelRatio||1,mobile?1.35:1.6);
      canvas.width=Math.round(w*dpr); canvas.height=Math.round(h*dpr);
      canvas.style.width=w+'px'; canvas.style.height=h+'px';
      ctx.setTransform(dpr,0,0,dpr,0,0); pile=new Array(Math.ceil(w/cell)+2).fill(0);
    }
    resize(); const onResize=()=>resize(); addEventListener('resize',onResize,{passive:true});
    const ground=x=>h-pile[Math.max(0,Math.min(pile.length-1,Math.floor(x/cell)))];
    function addParticle(){
      if(particles.length>=cap)return;
      let kind=season;
      if(season==='autumn')kind=Math.random()<.82?'leaf':'rain';
      particles.push({kind,x:Math.random()*w,y:-12-Math.random()*28,vx:(Math.random()-.5)*20,vy:8+Math.random()*18,
        size:kind==='snow'?2+Math.random()*3:kind==='rain'?7+Math.random()*8:5+Math.random()*8,
        a:Math.random()*Math.PI*2,spin:(Math.random()-.5)*(kind==='leaf'?4.2:2.2),
        sway:10+Math.random()*30,phase:Math.random()*8,alpha:.34+Math.random()*.48});
    }
    function settle(p){
      if(p.kind==='rain'||p.kind==='summer')return;
      const ix=Math.max(0,Math.min(pile.length-1,Math.floor(p.x/cell)));
      const amount=p.kind==='snow'?.78+p.size*.13:p.kind==='leaf'?.36:.22;
      for(let d=-2;d<=2;d++){const i=ix+d;if(i>=0&&i<pile.length)pile[i]=Math.min(p.kind==='snow'?72:34,pile[i]+amount*(1-Math.abs(d)*.19));}
      if(p.kind!=='snow'){settled.push(p);if(settled.length>420)settled.shift();}
    }
    function leaf(p,x,y,scale=1){
      ctx.save();ctx.translate(x,y);ctx.rotate(p.a);ctx.scale(scale,scale);ctx.globalAlpha=p.alpha;
      const g=ctx.createLinearGradient(-p.size,-p.size,p.size,p.size);g.addColorStop(0,'#f7c879');g.addColorStop(.55,'#c56b37');g.addColorStop(1,'#8e452e');
      ctx.fillStyle=g;ctx.beginPath();ctx.moveTo(0,-p.size*1.25);ctx.bezierCurveTo(p.size*.95,-p.size*.75,p.size*1.05,p.size*.25,0,p.size*1.15);ctx.bezierCurveTo(-p.size*1.05,p.size*.25,-p.size*.95,-p.size*.75,0,-p.size*1.25);ctx.fill();
      ctx.strokeStyle='rgba(255,226,176,.6)';ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(0,-p.size);ctx.lineTo(0,p.size*.9);ctx.stroke();ctx.restore();
    }
    function drawPile(){
      if(season==='winter'){
        const g=ctx.createLinearGradient(0,h-65,0,h);g.addColorStop(0,'rgba(203,235,255,.02)');g.addColorStop(1,'rgba(198,232,255,.23)');
        ctx.beginPath();ctx.moveTo(0,h);for(let i=0;i<pile.length;i++)ctx.lineTo(i*cell,h-pile[i]);ctx.lineTo(w,h);ctx.closePath();ctx.fillStyle=g;ctx.fill();
        ctx.strokeStyle='rgba(220,244,255,.28)';ctx.lineWidth=1;ctx.beginPath();for(let i=0;i<pile.length;i++){const x=i*cell,y=h-pile[i];i?ctx.lineTo(x,y):ctx.moveTo(x,y);}ctx.stroke();
      }
      for(const p of settled)leaf(p,p.x,ground(p.x)-2,.76);
    }
    function tick(now){
      if(document.hidden){last=now;weatherFrame=0;return;}
      const dt=Math.min(.034,Math.max(0,(now-(last||now))/1000));last=now;time+=dt;spawn+=dt*rate;
      while(spawn>=1){addParticle();spawn--;}
      ctx.clearRect(0,0,w,h);const wind=Math.sin(time*.31)*13+Math.sin(time*.13)*7;
      for(let i=particles.length-1;i>=0;i--){
        const p=particles[i];p.phase+=dt;p.vy=Math.min(p.vy+(p.kind==='snow'?12:p.kind==='rain'?90:p.kind==='summer'?3:24)*dt,p.kind==='rain'?210:78);
        p.vx+=(wind+Math.sin(p.phase*.9)*p.sway-p.vx)*dt*.16;p.x+=p.vx*dt;p.y+=p.vy*dt;p.a+=p.spin*dt;
        if(p.x< -24)p.x=w+20;if(p.x>w+24)p.x=-20;
        if(!['rain','summer'].includes(p.kind)&&p.y+p.size>=ground(p.x)){settle(p);particles.splice(i,1);continue;}
        if(p.y>h+24){particles.splice(i,1);continue;}
        if(p.kind==='leaf')leaf(p,p.x,p.y);
        else if(p.kind==='spring'){ctx.save();ctx.translate(p.x,p.y);ctx.rotate(p.a);ctx.globalAlpha=p.alpha;ctx.fillStyle='#f0b8ce';ctx.beginPath();ctx.ellipse(0,0,p.size*.45,p.size*1.05,0,0,Math.PI*2);ctx.fill();ctx.restore();}
        else if(p.kind==='snow'){ctx.save();ctx.globalAlpha=p.alpha;ctx.fillStyle='#e5f6ff';ctx.shadowColor='rgba(173,224,255,.75)';ctx.shadowBlur=p.size*2.8;ctx.beginPath();ctx.arc(p.x,p.y,p.size*.56,0,Math.PI*2);ctx.fill();ctx.restore();}
        else if(p.kind==='rain'){ctx.save();ctx.globalAlpha=p.alpha*.62;ctx.strokeStyle='rgba(160,207,239,.8)';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(p.x-3,p.y+p.size*1.6);ctx.stroke();ctx.restore();}
        else {ctx.save();ctx.globalAlpha=p.alpha*(.65+Math.sin(time*2+p.phase)*.3);ctx.fillStyle='#ffe6a8';ctx.shadowColor='#ffcf73';ctx.shadowBlur=14;ctx.beginPath();ctx.arc(p.x,p.y,p.size*.34,0,Math.PI*2);ctx.fill();ctx.restore();}
      }
      drawPile();weatherFrame=requestAnimationFrame(tick);
    }
    const onVisibility=()=>{if(!document.hidden&&!weatherFrame){last=0;weatherFrame=requestAnimationFrame(tick);}};
    document.addEventListener('visibilitychange',onVisibility);
    weatherCleanup=()=>{removeEventListener('resize',onResize);document.removeEventListener('visibilitychange',onVisibility);if(weatherFrame)cancelAnimationFrame(weatherFrame);weatherFrame=0;};
    weatherFrame=requestAnimationFrame(tick);
  }
  function applySeason(season){
    if(!seasons[season])season='autumn';
    currentSeason=season;root.dataset.season=season;
    const data=seasons[season];
    const nodes={
      'season-pill-emoji':data.emoji,'season-pill-name':data.code,
      'showcase-style':data.style,'showcase-mood':data.mood,
      'scene-symbol-one':({spring:'✿',summer:'☼',autumn:'✦',winter:'❄'})[season],
      'scene-symbol-two':season==='spring'?'🌸':season==='summer'?'✦':'✧',
      'scene-symbol-three':season==='autumn'?'·':'✧',
      'season-current-emoji':data.emoji,'season-current-label':data.label
    };
    Object.entries(nodes).forEach(([id,value])=>{const el=document.getElementById(id);if(el)el.textContent=value;});
    document.querySelectorAll('[data-admin-season]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.adminSeason===season)));
    if(effectKey!==season){effectKey=season;makeWeather(season);}
  }
  async function api(path,options){
    const response=await fetch(path,{cache:'no-store',credentials:'same-origin',...options,
      headers:{'Accept':'application/json',...(options&&options.headers?options.headers:{})}});
    let data={};try{data=await response.json();}catch(_){}
    if(!response.ok)throw new Error(data.error||'Запрос не выполнен.');
    return data;
  }
  async function refreshSeason(){try{const data=await api('/api/season',{method:'GET'});applySeason(data.season);}catch(_){applySeason(currentSeason);}}
  function setAdminView(value){if(loginView)loginView.hidden=value;if(panelView)panelView.hidden=!value;if(value)message(loginMessage,'',false);}
  async function checkAdmin(){
    try{const data=await api('/api/admin/session',{method:'GET'});setAdminView(Boolean(data.authenticated));}
    catch(_){setAdminView(false);message(loginMessage,'Админ-панель пока не подключена к общей базе.',true);}
  }
  function openModal(){
    if(!modal)return;modal.hidden=false;modal.setAttribute('aria-hidden','false');
    message(loginMessage,'',false);message(panelMessage,'',false);
    checkAdmin().then(()=>{if(loginView&&!loginView.hidden&&passwordField)passwordField.focus();});
  }
  function closeModal(){if(!modal)return;modal.hidden=true;modal.setAttribute('aria-hidden','true');if(passwordField)passwordField.value='';}
  const openButton=document.getElementById('admin-open');
  const closeButton=document.getElementById('admin-close');
  if(openButton)openButton.addEventListener('click',openModal);
  if(closeButton)closeButton.addEventListener('click',closeModal);
  if(modal)modal.addEventListener('click',event=>{if(event.target===modal)closeModal();});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&modal&&!modal.hidden)closeModal();});

  if(loginForm)loginForm.addEventListener('submit',async event=>{
    event.preventDefault();const submit=loginForm.querySelector('button[type="submit"]');submit.disabled=true;
    message(loginMessage,'Проверяем пароль…',false);
    try{
      await api('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:passwordField.value})});
      passwordField.value='';setAdminView(true);await refreshSeason();
      message(panelMessage,'Вход выполнен. Настройка действует на обеих страницах.',false);
    }catch(error){message(loginMessage,error.message,true);}
    finally{submit.disabled=false;}
  });
  document.querySelectorAll('[data-admin-season]').forEach(button=>button.addEventListener('click',async()=>{
    const season=button.dataset.adminSeason;
    document.querySelectorAll('[data-admin-season]').forEach(item=>item.disabled=true);
    message(panelMessage,'Сохраняем общую тему…',false);
    try{
      const data=await api('/api/admin/season',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({season})});
      applySeason(data.season);message(panelMessage,'Готово. Тема обновлена для всех посетителей обеих страниц.',false);
    }catch(error){message(panelMessage,error.message,true);}
    finally{document.querySelectorAll('[data-admin-season]').forEach(item=>item.disabled=false);}
  }));
  const logoutButton=document.getElementById('admin-logout');
  if(logoutButton)logoutButton.addEventListener('click',async()=>{
    try{await api('/api/admin/logout',{method:'POST'});}catch(_){}
    setAdminView(false);message(loginMessage,'Вы вышли из профиля.',false);
  });
  applySeason(currentSeason);refreshSeason();window.setInterval(refreshSeason,60000);
}());

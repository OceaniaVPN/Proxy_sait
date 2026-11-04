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
  function makeWeather(season){
    const layer=document.getElementById('weather-layer');if(!layer)return;
    if(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches){layer.replaceChildren();return;}
    layer.replaceChildren();
    const kind=season==='autumn'?(Math.random()<.5?'leaf':'rain'):season;
    const count=kind==='rain'?38:kind==='winter'?24:kind==='summer'?9:15;
    const icons={leaf:['🍂','🍁'],winter:['❄','✳'],spring:['🌸','✿'],summer:['✦','·']};
    for(let i=0;i<count;i++){
      const p=document.createElement('span');
      p.className='weather-particle '+(kind==='leaf'?'weather-leaf':kind==='rain'?'weather-rain':kind==='winter'?'weather-snow':kind==='spring'?'weather-petal':'weather-sparkle');
      if(kind!=='rain')p.textContent=icons[kind][Math.floor(Math.random()*icons[kind].length)];
      p.style.setProperty('--x',(Math.random()*100)+'vw');
      p.style.setProperty('--duration',((kind==='rain'?1.2:8)+Math.random()*(kind==='rain'?1.7:13))+'s');
      p.style.setProperty('--delay',(-Math.random()*18)+'s');
      p.style.setProperty('--size',(kind==='winter'?9+Math.random()*12:12+Math.random()*14)+'px');
      p.style.setProperty('--opacity',(0.18+Math.random()*.5).toFixed(2));
      p.style.setProperty('--drift',((Math.random()*18)-9)+'vw');
      layer.append(p);
    }
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

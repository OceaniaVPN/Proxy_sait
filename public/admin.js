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
    const layer=document.getElementById('weather-layer');
    if(!layer)return;
    if(weatherFrame)cancelAnimationFrame(weatherFrame);
    weatherFrame=0;
    layer.replaceChildren();
    layer.setAttribute('aria-hidden','true');
    const reducedMotion=Boolean(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    const mobile=window.matchMedia('(max-width:640px)').matches;
    const cap=reducedMotion?(mobile?12:18):(mobile?24:38);
    const spawnRate=reducedMotion?0.9:(mobile?1.7:2.5);
    const active=[],settled=[];
    const cell=28;
    let width=0,height=0,pile=[],last=0,spawn=0,elapsed=0,ground=null;
    layer.style.zIndex='0';
    layer.style.pointerEvents='none';
    function resize(){
      width=window.innerWidth;height=window.innerHeight;
      pile=new Array(Math.ceil(width/cell)+2).fill(0);
      if(ground)ground.style.height=(season==='winter'?Math.max(7,...pile):0)+'px';
    }
    resize();
    function groundY(x){
      const index=Math.max(0,Math.min(pile.length-1,Math.floor(x/cell)));
      return height-pile[index];
    }
    function iconFor(kind){
      const options={
        leaf:['🍂','🍁'],spring:['🌸','🌷','✿'],snow:['❄️','❅','✳'],summer:['✦','✧','☀️'],rain:['']
      };
      const list=options[kind]||options.leaf;
      return list[Math.floor(Math.random()*list.length)];
    }
    function buildNode(kind,size,opacity){
      const node=document.createElement('span');
      node.className='weather-live weather-live-'+kind;
      node.textContent=iconFor(kind);
      node.style.fontSize=size+'px';
      node.style.opacity=String(opacity);
      node.style.position='absolute';
      node.style.left='0';
      node.style.top='0';
      node.style.lineHeight='1';
      node.style.whiteSpace='nowrap';
      node.style.pointerEvents='none';
      node.style.userSelect='none';
      node.style.willChange='transform';
      return node;
    }
    function chooseKind(){
      if(season==='autumn')return Math.random()<.96?'leaf':'rain';
      return season==='spring'?'spring':season==='winter'?'snow':'summer';
    }
    function addParticle(initial=false){
      if(active.length>=cap)return;
      const kind=chooseKind();
      const size=kind==='snow'?11+Math.random()*8:kind==='rain'?10:19+Math.random()*12;
      const node=buildNode(kind,size,.72+Math.random()*.28);
      layer.append(node);
      const p={
        kind,node,x:Math.random()*width,
        y:initial?Math.random()*height*.76:-35-Math.random()*height*.25,
        vx:(Math.random()-.5)*18,
        vy:reducedMotion?7+Math.random()*7:13+Math.random()*20,
        angle:Math.random()*360,
        spin:(Math.random()-.5)*(kind==='leaf'?180:kind==='spring'?110:70),
        sway:kind==='leaf'?20+Math.random()*30:8+Math.random()*18,
        phase:Math.random()*Math.PI*2,
        size,
        settled:false
      };
      node.style.transform='translate3d('+p.x+'px,'+p.y+'px,0) rotate('+p.angle+'deg)';
      active.push(p);
    }
    function settleParticle(p){
      const index=Math.max(0,Math.min(pile.length-1,Math.floor(p.x/cell)));
      const amount=p.kind==='snow'?2.2:p.kind==='leaf'?2.5:1.1;
      for(let offset=-1;offset<=1;offset++){
        const i=index+offset;
        if(i>=0&&i<pile.length)pile[i]=Math.min(p.kind==='snow'?64:34,pile[i]+amount*(offset===0?1:.46));
      }
      p.y=groundY(p.x)-p.size*.56;
      p.node.classList.add('weather-live-settled');
      p.node.style.opacity=p.kind==='leaf'?'.88':'.82';
      p.node.style.transform='translate3d('+p.x+'px,'+p.y+'px,0) rotate('+p.angle+'deg)';
      p.node.style.willChange='auto';
      settled.push(p);
      if(settled.length>100){
        const old=settled.shift();
        old.node.remove();
      }
    }
    function frame(now){
      if(document.hidden){last=now;weatherFrame=0;return;}
      const dt=Math.min(.04,Math.max(0,(now-(last||now))/1000));
      last=now;elapsed+=dt;spawn+=dt*spawnRate;
      while(spawn>=1){addParticle(false);spawn-=1;}
      const wind=(Math.sin(elapsed*.31)*18+Math.sin(elapsed*.13)*10)*(reducedMotion?.38:1);
      for(let i=active.length-1;i>=0;i--){
        const p=active[i];
        p.phase+=dt;
        p.vy=Math.min(p.vy+(p.kind==='rain'?95:p.kind==='snow'?12:p.kind==='summer'?2:28)*dt*(reducedMotion?.45:1),p.kind==='rain'?180:reducedMotion?28:78);
        p.vx+=(wind+Math.sin(p.phase)*p.sway-p.vx)*dt*.18;
        p.x+=p.vx*dt;
        p.y+=p.vy*dt;
        p.angle+=p.spin*dt;
        if(p.x< -45)p.x=width+30;
        if(p.x>width+45)p.x=-30;
        if(p.kind!=='rain'&&p.kind!=='summer'&&p.y+p.size*.6>=groundY(p.x)){
          settleParticle(p);
          active.splice(i,1);
          continue;
        }
        if(p.y>height+45){
          p.node.remove();active.splice(i,1);continue;
        }
        p.node.style.transform='translate3d('+p.x+'px,'+p.y+'px,0) rotate('+p.angle+'deg)';
      }
      if(ground){
        const peak=Math.max(0,...pile);
        ground.style.height=(season==='winter'?Math.min(64,peak+7):0)+'px';
        ground.style.opacity=season==='winter'?'1':'0';
      }
      weatherFrame=requestAnimationFrame(frame);
    }
    ground=document.createElement('div');
    ground.className='weather-live-ground';
    ground.style.position='absolute';
    ground.style.left='0';ground.style.right='0';ground.style.bottom='0';
    ground.style.height='0';ground.style.pointerEvents='none';
    if(season==='winter')layer.append(ground);
    // Seed the scene immediately so the first leaves are visible without waiting for a full fall.
    const initialCount=Math.min(cap,season==='autumn'?(mobile?13:20):(mobile?8:14));
    for(let i=0;i<initialCount;i++)addParticle(true);
    const onResize=()=>resize();
    const onVisibility=()=>{if(!document.hidden&&!weatherFrame){last=0;weatherFrame=requestAnimationFrame(frame);}};
    window.addEventListener('resize',onResize,{passive:true});
    document.addEventListener('visibilitychange',onVisibility);
    weatherCleanup=()=>{
      window.removeEventListener('resize',onResize);
      document.removeEventListener('visibilitychange',onVisibility);
      if(weatherFrame)cancelAnimationFrame(weatherFrame);
      weatherFrame=0;
    };
    weatherFrame=requestAnimationFrame(frame);
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

  // Секретная мини-игра: пять быстрых нажатий на логотип.
  const gameModal=document.getElementById('easter-game-modal');
  const gameClose=document.getElementById('easter-game-close');
  const gameStart=document.getElementById('easter-game-start');
  const gameArena=document.getElementById('easter-game-arena');
  const gameHint=document.getElementById('easter-game-hint');
  const gameScoreNode=document.getElementById('easter-game-score');
  const gameTimeNode=document.getElementById('easter-game-time');
  const gameStatus=document.getElementById('easter-game-status');
  let gameScore=0,gameTime=20,gameRunning=false,gameSpawnTimer=0,gameClockTimer=0;
  let brandHits=0,brandHitTimeout=0;

  function stopMiniGame(){
    gameRunning=false;
    if(gameSpawnTimer)clearInterval(gameSpawnTimer);
    if(gameClockTimer)clearInterval(gameClockTimer);
    gameSpawnTimer=0;gameClockTimer=0;
  }
  function closeMiniGame(){
    stopMiniGame();
    if(gameModal){gameModal.hidden=true;gameModal.setAttribute('aria-hidden','true');}
  }
  function openMiniGame(){
    if(!gameModal)return;
    stopMiniGame();
    gameScore=0;gameTime=20;
    gameScoreNode.textContent='0';gameTimeNode.textContent='20';
    gameArena.replaceChildren(gameHint);gameHint.hidden=false;
    gameHint.textContent='Нажми «Начать игру», чтобы открыть сезонную охоту.';
    gameStart.hidden=false;gameStart.textContent='Начать игру';
    gameStatus.textContent='Секрет STEKLOVPN найден ✦';
    gameModal.hidden=false;gameModal.setAttribute('aria-hidden','false');
  }
  function spawnGameTarget(){
    if(!gameRunning||gameArena.querySelectorAll('.game-target').length>=9)return;
    const target=document.createElement('button');
    target.type='button';target.className='game-target';
    target.setAttribute('aria-label','Поймать частицу');
    const icons=currentSeason==='winter'?['❄️','✳️']:currentSeason==='spring'?['🌸','🌷']:currentSeason==='summer'?['✦','☀️']:['🍂','🍁'];
    target.textContent=icons[Math.floor(Math.random()*icons.length)];
    target.style.setProperty('--gx',(9+Math.random()*82)+'%');
    target.style.setProperty('--gy',(13+Math.random()*72)+'%');
    target.addEventListener('click',()=>{
      if(!gameRunning)return;
      gameScore++;gameScoreNode.textContent=String(gameScore);
      target.remove();
      if(gameScore===10)gameStatus.textContent='Отлично! Уже 10 частиц ✨';
    });
    gameArena.append(target);
    window.setTimeout(()=>target.remove(),2800);
  }
  function finishMiniGame(){
    stopMiniGame();
    gameStart.hidden=false;gameStart.textContent='Играть ещё раз';
    gameStatus.textContent=gameScore>=20?'Невероятно! Ты поймал '+gameScore+' частиц! 🏆':'Время вышло! Результат: '+gameScore+'. Попробуешь ещё?';
  }
  function startMiniGame(){
    stopMiniGame();gameArena.replaceChildren();gameScore=0;gameTime=20;gameRunning=true;
    gameScoreNode.textContent='0';gameTimeNode.textContent='20';
    gameStart.hidden=true;gameStatus.textContent='Лови частицы!';
    spawnGameTarget();gameSpawnTimer=window.setInterval(spawnGameTarget,620);
    gameClockTimer=window.setInterval(()=>{
      gameTime=Math.max(0,gameTime-1);gameTimeNode.textContent=String(gameTime);
      if(gameTime<=0)finishMiniGame();
    },1000);
  }
  if(gameClose)gameClose.addEventListener('click',closeMiniGame);
  if(gameStart)gameStart.addEventListener('click',startMiniGame);
  if(gameModal)gameModal.addEventListener('click',event=>{if(event.target===gameModal)closeMiniGame();});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&gameModal&&!gameModal.hidden)closeMiniGame();});
  const brandLink=document.querySelector('.brand');
  if(gameModal&&brandLink)brandLink.addEventListener('click',event=>{
    brandHits++;
    if(brandHitTimeout)clearTimeout(brandHitTimeout);
    brandHitTimeout=window.setTimeout(()=>{brandHits=0;},1900);
    if(brandHits>=5){event.preventDefault();brandHits=0;openMiniGame();}
  });

  applySeason(currentSeason);refreshSeason();window.setInterval(refreshSeason,60000);
}());

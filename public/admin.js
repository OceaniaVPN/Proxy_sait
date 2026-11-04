(function () {
  'use strict';

  const root = document.documentElement;
  const meta = {
    spring: { emoji: '🌸', label: 'Весна', code: 'SPRING MODE', style: 'Свежий и лёгкий', mood: 'Время цветения' },
    summer: { emoji: '☀️', label: 'Лето', code: 'SUMMER MODE', style: 'Яркий и солнечный', mood: 'Тёплое сияние' },
    autumn: { emoji: '🍂', label: 'Осень', code: 'AUTUMN MODE', style: 'Тёплый и уютный', mood: 'Золотой свет' },
    winter: { emoji: '❄️', label: 'Зима', code: 'WINTER MODE', style: 'Спокойный и чистый', mood: 'Морозное сияние' }
  };
  const modal = document.getElementById('admin-modal');
  const loginView = document.getElementById('admin-login-view');
  const panelView = document.getElementById('admin-panel-view');
  const loginForm = document.getElementById('admin-login-form');
  const loginMessage = document.getElementById('admin-login-message');
  const panelMessage = document.getElementById('admin-message');
  const passwordField = document.getElementById('admin-password');
  let currentSeason = root.dataset.season || 'autumn';
  let effectKey = '';

  function showMessage(element, message, isError) {
    if (!element) return;
    element.textContent = message || '';
    element.classList.toggle('error', Boolean(isError));
  }

  function makeWeather(season) {
    const layer = document.getElementById('weather-layer');
    if (!layer) return;
    const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    layer.replaceChildren();
    if (reduced) return;

    let kind = season;
    if (season === 'autumn') kind = Math.random() < 0.5 ? 'leaf' : 'rain';
    const count = kind === 'rain' ? 38 : kind === 'winter' ? 24 : kind === 'summer' ? 9 : 15;
    const symbols = {
      leaf: ['🍂', '🍁'], snow: ['❄', '✳'], spring: ['🌸', '✿', '·'], summer: ['✦', '·']
    };
    for (let i = 0; i < count; i++) {
      const particle = document.createElement('span');
      particle.className = 'weather-particle ' + (
        kind === 'leaf' ? 'weather-leaf' :
        kind === 'rain' ? 'weather-rain' :
        kind === 'winter' ? 'weather-snow' :
        kind === 'spring' ? 'weather-petal' : 'weather-sparkle'
      );
      if (kind !== 'rain') {
        const key = kind === 'winter' ? 'snow' : kind;
        particle.textContent = symbols[key][Math.floor(Math.random() * symbols[key].length)];
      }
      particle.style.setProperty('--x', (Math.random() * 100) + 'vw');
      particle.style.setProperty('--duration', ((kind === 'rain' ? 1.2 : 8) + Math.random() * (kind === 'rain' ? 1.7 : 13)) + 's');
      particle.style.setProperty('--delay', (-Math.random() * 18) + 's');
      particle.style.setProperty('--size', (kind === 'winter' ? 9 + Math.random() * 12 : 12 + Math.random() * 14) + 'px');
      particle.style.setProperty('--opacity', (0.18 + Math.random() * 0.5).toFixed(2));
      particle.style.setProperty('--drift', ((Math.random() * 18) - 9) + 'vw');
      layer.append(particle);
    }
  }

  function applySeason(season) {
    if (!meta[season]) season = 'autumn';
    currentSeason = season;
    root.dataset.season = season;
    const data = meta[season];
    const emoji = document.getElementById('season-pill-emoji');
    const name = document.getElementById('season-pill-name');
    const style = document.getElementById('showcase-style');
    const mood = document.getElementById('showcase-mood');
    const symbolOne = document.getElementById('scene-symbol-one');
    const symbolTwo = document.getElementById('scene-symbol-two');
    const symbolThree = document.getElementById('scene-symbol-three');
    const currentEmoji = document.getElementById('season-current-emoji');
    const currentLabel = document.getElementById('season-current-label');
    if (emoji) emoji.textContent = data.emoji;
    if (name) name.textContent = data.code;
    if (style) style.textContent = data.style;
    if (mood) mood.textContent = data.mood;
    if (symbolOne) symbolOne.textContent = ({ spring:'✿',summer:'☼',autumn:'✦',winter:'❄' })[season];
    if (symbolTwo) symbolTwo.textContent = season === 'spring' ? '🌸' : season === 'summer' ? '✦' : '✧';
    if (symbolThree) symbolThree.textContent = season === 'autumn' ? '·' : '✧';
    if (currentEmoji) currentEmoji.textContent = data.emoji;
    if (currentLabel) currentLabel.textContent = data.label;
    document.querySelectorAll('[data-admin-season]').forEach(button => {
      button.setAttribute('aria-pressed', String(button.dataset.adminSeason === season));
    });
    if (effectKey !== season) {
      effectKey = season;
      makeWeather(season);
    }
  }

  async function api(path, options) {
    const response = await fetch(path, {
      cache: 'no-store',
      credentials: 'same-origin',
      ...options,
      headers: { 'Accept': 'application/json', ...(options && options.headers ? options.headers : {}) }
    });
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (!response.ok) throw new Error(data.error || 'Запрос не выполнен.');
    return data;
  }

  async function refreshSeason() {
    try {
      const data = await api('/api/season', { method: 'GET' });
      applySeason(data.season);
    } catch (_) {
      applySeason(currentSeason);
    }
  }

  async function checkAdmin() {
    try {
      const data = await api('/api/admin/session', { method: 'GET' });
      setAdminView(Boolean(data.authenticated));
    } catch (_) {
      setAdminView(false);
      showMessage(loginMessage, 'Админ-панель пока не подключена к общей базе.', true);
    }
  }

  function setAdminView(isAdmin) {
    if (loginView) loginView.hidden = isAdmin;
    if (panelView) panelView.hidden = !isAdmin;
    if (isAdmin) showMessage(loginMessage, '', false);
  }

  function openModal() {
    if (!modal) return;
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    showMessage(loginMessage, '', false);
    showMessage(panelMessage, '', false);
    checkAdmin().then(() => {
      if (loginView && !loginView.hidden && passwordField) passwordField.focus();
    });
  }
  function closeModal() {
    if (!modal) return;
    modal.hidden = true;
    modal.setAttribute('aria-hidden', 'true');
    if (passwordField) passwordField.value = '';
  }

  const openButton = document.getElementById('admin-open');
  const closeButton = document.getElementById('admin-close');
  if (openButton) openButton.addEventListener('click', openModal);
  if (closeButton) closeButton.addEventListener('click', closeModal);
  if (modal) modal.addEventListener('click', event => { if (event.target === modal) closeModal(); });
  document.addEventListener('keydown', event => { if (event.key === 'Escape' && modal && !modal.hidden) closeModal(); });

  if (loginForm) loginForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = loginForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    showMessage(loginMessage, 'Проверяем пароль…', false);
    try {
      await api('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: passwordField.value })
      });
      passwordField.value = '';
      setAdminView(true);
      await refreshSeason();
      showMessage(panelMessage, 'Вход выполнен. Настройка действует на обеих страницах.', false);
    } catch (error) {
      showMessage(loginMessage, error.message, true);
    } finally {
      submit.disabled = false;
    }
  });

  document.querySelectorAll('[data-admin-season]').forEach(button => {
    button.addEventListener('click', async () => {
      const season = button.dataset.adminSeason;
      document.querySelectorAll('[data-admin-season]').forEach(item => { item.disabled = true; });
      showMessage(panelMessage, 'Сохраняем общую тему…', false);
      try {
        const data = await api('/api/admin/season', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ season })
        });
        applySeason(data.season);
        showMessage(panelMessage, 'Готово. Тема обновлена для всех посетителей обеих страниц.', false);
      } catch (error) {
        showMessage(panelMessage, error.message, true);
      } finally {
        document.querySelectorAll('[data-admin-season]').forEach(item => { item.disabled = false; });
      }
    });
  });

  const logoutButton = document.getElementById('admin-logout');
  if (logoutButton) logoutButton.addEventListener('click', async () => {
    try { await api('/api/admin/logout', { method: 'POST' }); } catch (_) {}
    setAdminView(false);
    showMessage(loginMessage, 'Вы вышли из профиля.', false);
  });

  applySeason(currentSeason);
  refreshSeason();
  window.setInterval(refreshSeason, 60000);
}());

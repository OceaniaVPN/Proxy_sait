# Proxy Sait

Каталог прокси с поиском, фильтрами и копированием строки подключения. Статические файлы обслуживаются Cloudflare Workers Static Assets через Wrangler.

## Деплой на Cloudflare

Нужны Node.js и аккаунт Cloudflare.

1. Склонируй репозиторий:
   `git clone https://github.com/OceaniaVPN/Proxy_sait.git`
2. Перейди в папку:
   `cd Proxy_sait`
3. Установи Wrangler и войди в Cloudflare:
   `npm install --save-dev wrangler`
   `npx wrangler login`
4. Запусти локальный предпросмотр:
   `npx wrangler dev`
5. Опубликуй сайт:
   `npx wrangler deploy`

Конфигурация находится в `wrangler.jsonc`; каталог статических файлов — корень репозитория. После успешного деплоя Wrangler покажет URL вида `https://proxy-sait.<твой-subdomain>.workers.dev`.

## Данные прокси

Список загружается из `data/proxies.json`. Сейчас там только демонстрационные адреса `.example`, они не работают. Замени их на свои записи. Не добавляй в публичный репозиторий секреты, приватные ключи или конфигурации, которые не должны быть общедоступными.

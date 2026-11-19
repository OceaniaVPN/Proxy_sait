# GitHub Pages migration

This branch prepares the static frontend for GitHub Pages while leaving the existing Cloudflare Worker and D1 database in place.

## Architecture
- Static files are published from `public/` by `.github/workflows/pages.yml`.
- The proxy catalogue API remains on `https://proxy-sait.novogodniysait.workers.dev`.
- The main-site API remains on `https://steklovpn-site.novogodniysait.workers.dev`.
- No DNS changes or Cloudflare domain binding are required.
- Existing Worker deployments and D1 data must remain enabled.

## First-time GitHub Pages setup
1. Open repository **Settings → Pages**.
2. Under **Build and deployment**, select **GitHub Actions** as the source.
3. Push/merge this branch when ready; the workflow publishes the `public/` directory.
4. The expected project URLs are:
   - `https://oceaniavpn.github.io/Proxy_sait/`
   - `https://oceaniavpn.github.io/STEKLOVPN-Site/`

## Worker CORS
The Worker API changes allow credentialed browser requests from `https://oceaniavpn.github.io`. Admin session cookies use `SameSite=None; Secure` because Pages and Workers are different sites. Keep the Worker admin secrets configured in Cloudflare; never put them in GitHub files.

## Important
This is a staging branch. The Pages workflow runs only after GitHub Pages is configured to use GitHub Actions. Test both sites and admin login before merging to `main`. Do not remove the existing Worker static assets or D1 bindings during this migration.

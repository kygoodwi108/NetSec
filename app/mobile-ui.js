/* NetSec 1.1.1 — small-screen presentation only; existing pages remain authoritative. */
(() => {
  'use strict';
  const mq = window.matchMedia('(max-width: 900px)');
  const hub = document.querySelector('.nav');
  const command = document.getElementById('hub-tab-command');
  if (!hub || !command || !hub.querySelector('[data-hub-tab="command"]')) return;

  const node = (tag, cls, txt) => {
    const x = document.createElement(tag);
    if (cls) x.className = cls;
    if (txt !== undefined) x.textContent = txt;
    return x;
  };

  // This panel mirrors existing DOM metrics; it does not fetch or reinterpret evidence.
  const glance = node('section', 'mobile-glance');
  glance.setAttribute('aria-label', 'Mobile security summary');
  const glanceHead = node('div', 'mobile-glance-head');
  glanceHead.append(node('strong', '', 'At a glance'), node('span', '', 'Read-only telemetry'));
  glance.append(glanceHead);
  const cards = node('div', 'mobile-glance-cards');
  const measures = [
    ['Traffic signal', 'riskLabel', 'mobileTrafficSignal'],
    ['Service checks', 'svcHealth', 'mobileServices'],
    ['Requests / 24h', 'hubRequests', 'mobileRequests'],
    ['HTTP 401 + 403', 'hubDenied', 'mobileDenied']
  ];
  for (const [label, , id] of measures) {
    const card = node('div', 'mobile-glance-card');
    card.append(node('small', '', label));
    const value = node('strong', '', '—');
    value.id = id;
    card.append(value);
    cards.append(card);
  }
  glance.append(cards);
  const jimmy = node('button', 'mobile-jimmy-link', '✦  Review with Jimmy');
  jimmy.type = 'button';
  jimmy.addEventListener('click', () => navigate('jimmy'));
  glance.append(jimmy);
  command.querySelector('.hub-sectionhead')?.after(glance);

  const dock = node('nav', 'mobile-dock');
  dock.setAttribute('aria-label', 'Mobile dashboard navigation');
  const definitions = [
    ['command', '⌂', 'Home'],
    ['jimmy', '✦', 'Jimmy'],
    ['connections', '◎', 'IPs'],
    ['investigate', '≡', 'Events']
  ];
  const buttons = new Map();
  const makeButton = ([key, icon, label]) => {
    const button = node('button', 'mobile-dock-button');
    button.type = 'button';
    button.dataset.mobileTab = key;
    button.setAttribute('aria-label', label === 'IPs' ? 'IP Connections' : label === 'Events' ? 'Investigations' : label);
    const symbol = node('span', 'mobile-dock-icon', icon);
    symbol.setAttribute('aria-hidden', 'true');
    button.append(symbol, node('span', 'mobile-dock-label', label));
    button.addEventListener('click', () => navigate(key));
    buttons.set(key, button);
    return button;
  };
  for (const def of definitions) dock.append(makeButton(def));
  const more = node('button', 'mobile-dock-button');
  more.type = 'button';
  more.setAttribute('aria-label', 'More dashboard pages');
  more.setAttribute('aria-expanded', 'false');
  more.setAttribute('aria-controls', 'netsecMobileMore');
  const moreIcon = node('span', 'mobile-dock-icon', '⋯');
  moreIcon.setAttribute('aria-hidden', 'true');
  more.append(moreIcon, node('span', 'mobile-dock-label', 'More'));
  dock.append(more);

  const moreMenu = node('div', 'mobile-more');
  moreMenu.id = 'netsecMobileMore';
  moreMenu.hidden = true;
  moreMenu.setAttribute('aria-label', 'Other dashboard pages');
  for (const [key, label, icon] of [['traffic', 'Traffic analytics', '▥'], ['intel', 'Source intelligence', '◈']]) {
    const item = node('button', 'mobile-more-item', `${icon}  ${label}`);
    item.type = 'button';
    item.dataset.mobileTab = key;
    item.addEventListener('click', () => navigate(key));
    moreMenu.append(item);
  }
  document.body.append(moreMenu, dock);

  function openMore(open) {
    moreMenu.hidden = !open;
    more.setAttribute('aria-expanded', String(open));
    more.classList.toggle('menu-open', open);
    if (open) moreMenu.querySelector('button')?.focus();
  }
  more.addEventListener('click', () => openMore(moreMenu.hidden));
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !moreMenu.hidden) {
      openMore(false);
      more.focus();
    }
  });
  document.addEventListener('pointerdown', e => {
    if (!moreMenu.hidden && !more.contains(e.target) && !moreMenu.contains(e.target)) openMore(false);
  });
  mq.addEventListener('change', e => { if (!e.matches) openMore(false); });

  function activeKey() {
    return hub.querySelector('[data-hub-tab].active')?.dataset.hubTab ||
      location.hash.slice(1).split('&')[0] || 'command';
  }
  function syncNav() {
    const current = activeKey();
    for (const [key, button] of buttons) {
      const selected = key === current;
      button.classList.toggle('active', selected);
      if (selected) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    const inMore = current === 'traffic' || current === 'intel';
    more.classList.toggle('active', inMore);
    if (inMore) more.setAttribute('aria-current', 'page');
    else more.removeAttribute('aria-current');
    for (const button of moreMenu.querySelectorAll('button')) {
      if (button.dataset.mobileTab === current) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
  }
  function navigate(key) {
    const target = hub.querySelector(`[data-hub-tab="${key}"]`);
    if (!target) return;
    openMore(false);
    target.click(); // Reuse the dashboard's existing page/routing and loading logic.
    syncNav();
    document.querySelector('main.main')?.focus({preventScroll:true});
  }
  // The original tab controller uses history.replaceState, which does not fire hashchange.
  new MutationObserver(syncNav).observe(hub, {subtree:true, attributes:true, attributeFilter:['class','aria-selected']});
  window.addEventListener('hashchange', syncNav);
  syncNav();

  let glanceScheduled = false;
  function syncGlance() {
    glanceScheduled = false;
    for (const [, source, destination] of measures) {
      const from = document.getElementById(source);
      const to = document.getElementById(destination);
      if (from && to) to.textContent = (from.textContent || '').trim() || '—';
    }
    const red = document.querySelector('#lights .bulb.red.on');
    const amber = document.querySelector('#lights .bulb.amber.on');
    const green = document.querySelector('#lights .bulb.green.on');
    document.getElementById('mobileTrafficSignal').dataset.level = red ? 'red' : amber ? 'amber' : green ? 'green' : 'unknown';
  }
  function scheduleGlance() {
    if (!glanceScheduled) {
      glanceScheduled = true;
      window.requestAnimationFrame(syncGlance);
    }
  }
  for (const [, source] of measures) {
    const el = document.getElementById(source);
    if (el) new MutationObserver(scheduleGlance).observe(el, {childList:true, subtree:true, characterData:true});
  }
  const lights = document.getElementById('lights');
  if (lights) new MutationObserver(scheduleGlance).observe(lights, {subtree:true, attributes:true, attributeFilter:['class']});
  syncGlance();

  // Data tables are rendered by the original dashboard. Add semantic per-cell labels
  // without changing any values, links, actions, row order, or desktop presentation.
  const mobileTables = ['hubConnRows', 'recentRows', 'recentProbes', 'crowdsecRows',
    'intelCandidates', 'intelLabels', 'intelHistory'];
  for (const id of mobileTables) {
    const tbody = document.getElementById(id);
    if (!tbody) continue;
    const table = tbody.closest('table');
    if (!table) continue;
    table.classList.add('mobile-card-table');
    const headers = Array.from(table.querySelectorAll('thead th'), th => th.textContent.trim());
    function annotate() {
      for (const row of tbody.rows) {
        if (row.cells.length === 1 && row.cells[0].colSpan > 1) {
          row.classList.add('mobile-empty-row');
          continue;
        }
        for (const [i, td] of Array.from(row.cells).entries()) {
          td.dataset.mobileLabel = headers[i] || 'Detail';
        }
      }
    }
    annotate();
    new MutationObserver(annotate).observe(tbody, {childList:true});
  }
})();

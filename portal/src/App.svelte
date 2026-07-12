<script>
  import { onMount } from 'svelte';
  import { api } from './api.js';
  import Dashboard from './Dashboard.svelte';
  import Secrets from './Secrets.svelte';
  import Keys from './Keys.svelte';
  import Certificates from './Certificates.svelte';
  import Deleted from './Deleted.svelte';
  import Clock from './Clock.svelte';
  import Faults from './Faults.svelte';

  const views = {
    dashboard: { label: 'Dashboard', component: Dashboard, group: 'Vault' },
    secrets: { label: 'Secrets', component: Secrets, group: 'Vault' },
    keys: { label: 'Keys', component: Keys, group: 'Vault' },
    certificates: { label: 'Certificates', component: Certificates, group: 'Vault' },
    deleted: { label: 'Deleted', component: Deleted, group: 'Vault' },
    clock: { label: 'Clock', component: Clock, group: 'Testing tools' },
    faults: { label: 'Fault injection', component: Faults, group: 'Testing tools' },
  };
  const groups = ['Vault', 'Testing tools'];

  let route = $state(location.hash.slice(1) || 'dashboard');
  let healthy = $state(null);
  const current = $derived(views[route] ?? views.dashboard);

  onMount(() => {
    const onHash = () => (route = location.hash.slice(1) || 'dashboard');
    window.addEventListener('hashchange', onHash);
    const ping = async () => {
      try {
        await api.get('/health');
        healthy = true;
      } catch {
        healthy = false;
      }
    };
    ping();
    const t = setInterval(ping, 5000);
    return () => {
      window.removeEventListener('hashchange', onHash);
      clearInterval(t);
    };
  });
</script>

<div class="shell">
  <header>
    <div class="brand">
      <span class="wordmark">Azure Key Vault Emulator</span>
      <span class="badge">LOCAL EMULATOR</span>
    </div>
    <div class="health">
      <span class="dot" class:up={healthy === true} class:down={healthy === false}></span>
      {healthy === true ? 'healthy' : healthy === false ? 'unreachable' : '…'}
    </div>
  </header>
  <div class="body">
    <nav>
      {#each groups as group}
        <div class="navgroup">{group}</div>
        {#each Object.entries(views).filter(([, v]) => v.group === group) as [key, v]}
          <a href="#{key}" class="navitem" class:active={route === key}>{v.label}</a>
        {/each}
      {/each}
    </nav>
    <main>
      <current.component />
    </main>
  </div>
</div>

<style>
  .shell { display: flex; flex-direction: column; height: 100vh; }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .wordmark { font-weight: 600; font-size: 16px; }
  .health { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 13px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
  .dot.up { background: var(--ok); }
  .dot.down { background: var(--danger); }
  .body { display: flex; flex: 1; min-height: 0; }
  nav {
    width: 200px;
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 12px 0;
    overflow-y: auto;
  }
  .navgroup {
    padding: 12px 20px 4px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    font-weight: 600;
  }
  .navitem { display: block; padding: 7px 20px; color: var(--text); }
  .navitem:hover { background: var(--canvas); text-decoration: none; }
  .navitem.active { background: #eff6fc; color: var(--primary); box-shadow: inset 3px 0 var(--primary); font-weight: 600; }
  main { flex: 1; overflow-y: auto; padding: 24px; }
</style>

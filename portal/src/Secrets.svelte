<script>
  import { onMount } from 'svelte';
  import { api, fmtTime } from './api.js';

  let items = $state(null);
  let error = $state('');

  async function load() {
    error = '';
    try {
      items = (await api.get('/_emulator/portal/data/secrets')).value;
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
</script>

<h1>Secrets</h1>
{#if error}
  <p class="error">{error}</p>
{:else if items === null}
  <p class="muted">Loading…</p>
{:else if items.length === 0}
  <p class="empty">No secrets. Set one with the Azure SDK or REST, then refresh.</p>
{:else}
  <table>
    <thead><tr><th>Name</th><th>Vault</th><th>State</th><th>Content type</th><th>Version</th><th>Updated</th></tr></thead>
    <tbody>
      {#each items as it}
        <tr>
          <td>{it.name}</td>
          <td class="mono">{it.vault}</td>
          <td><span class="chip" class:on={it.enabled} class:off={!it.enabled}>{it.enabled ? 'enabled' : 'disabled'}</span></td>
          <td>{it.contentType || '—'}</td>
          <td class="mono">{it.version.slice(0, 8)}</td>
          <td>{fmtTime(it.updated)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

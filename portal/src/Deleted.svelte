<script>
  import { onMount } from 'svelte';
  import { api, fmtTime } from './api.js';

  let items = $state(null);
  let error = $state('');

  async function load() {
    error = '';
    try {
      items = (await api.get('/_emulator/portal/data/deleted')).value;
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
</script>

<h1>Deleted objects</h1>
<p class="muted">Soft-deleted objects awaiting their scheduled purge (or recovery).</p>
{#if error}
  <p class="error">{error}</p>
{:else if items === null}
  <p class="muted">Loading…</p>
{:else if items.length === 0}
  <p class="empty">Nothing in the soft-delete window.</p>
{:else}
  <table>
    <thead><tr><th>Name</th><th>Type</th><th>Vault</th><th>Deleted</th><th>Scheduled purge</th></tr></thead>
    <tbody>
      {#each items as it}
        <tr>
          <td>{it.name}</td>
          <td><span class="chip {it.type}">{it.type}</span></td>
          <td class="mono">{it.vault}</td>
          <td>{fmtTime(it.deletedDate)}</td>
          <td>{fmtTime(it.scheduledPurgeDate)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

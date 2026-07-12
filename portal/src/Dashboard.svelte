<script>
  import { onMount } from 'svelte';
  import { api, fmtTime } from './api.js';

  let data = $state(null);
  let error = $state('');

  async function load() {
    error = '';
    try {
      data = await api.get('/_emulator/portal/data/overview');
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);

  const cards = $derived(
    data
      ? [
          { label: 'Secrets', n: data.counts.secrets },
          { label: 'Keys', n: data.counts.keys },
          { label: 'Certificates', n: data.counts.certificates },
          { label: 'Deleted secrets', n: data.counts.deletedSecrets },
          { label: 'Deleted keys', n: data.counts.deletedKeys },
          { label: 'Deleted certs', n: data.counts.deletedCertificates },
        ]
      : [],
  );
</script>

<h1>Dashboard</h1>
<p class="muted">Live view of the emulator's stored objects, aggregated across every vault.</p>

{#if error}
  <p class="error">{error}</p>
{:else if data}
  <div class="cards">
    {#each cards as c}
      <div class="card">
        <div class="num">{c.n}</div>
        <div class="muted">{c.label}</div>
      </div>
    {/each}
  </div>

  <div class="card" style="margin-top:16px">
    <h2>Environment</h2>
    <div class="field"><span class="lbl">Vaults</span>{data.vaults?.length ? data.vaults.join(', ') : '(none yet)'}</div>
    <div class="field"><span class="lbl">Default vault</span><span class="mono">{data.defaultVault}</span></div>
    <div class="field"><span class="lbl">Clock</span>{data.clock.frozen ? 'frozen' : 'running'} · offset {data.clock.offset}s · {fmtTime(data.clock.now)}</div>
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}

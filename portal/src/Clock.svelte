<script>
  import { onMount } from 'svelte';
  import { api, fmtTime } from './api.js';

  let state = $state(null);
  let error = $state('');
  let advanceBy = $state(3600);

  async function load() {
    error = '';
    try {
      state = await api.get('/_emulator/clock');
    } catch (e) {
      error = e.message;
    }
  }
  async function post(body) {
    error = '';
    try {
      state = await api.post('/_emulator/clock', body);
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
</script>

<h1>Clock</h1>
<p class="muted">The controllable clock drives every attribute window, expiry, and purge deadline — freeze or advance it to make time-dependent tests deterministic.</p>

{#if error}<p class="error">{error}</p>{/if}
{#if state}
  <div class="card" style="max-width:520px">
    <div class="field"><span class="lbl">Now</span>{fmtTime(state.now)}</div>
    <div class="field"><span class="lbl">Offset</span>{state.offset}s</div>
    <div class="field"><span class="lbl">State</span><span class="chip" class:off={state.frozen} class:on={!state.frozen}>{state.frozen ? 'frozen' : 'running'}</span></div>

    <div class="field">
      <span class="lbl">Advance by (s)</span>
      <input type="number" bind:value={advanceBy} />
      <button class="btn" onclick={() => post({ advance: Number(advanceBy) })}>Advance</button>
    </div>
    <div class="field">
      <span class="lbl"></span>
      {#if state.frozen}
        <button class="btn btn-secondary" onclick={() => post({ freeze: false })}>Unfreeze</button>
      {:else}
        <button class="btn btn-secondary" onclick={() => post({ freeze: true })}>Freeze</button>
      {/if}
      <button class="btn btn-secondary" onclick={() => post({ offset: 0, freeze: false })}>Reset</button>
    </div>
  </div>
{/if}

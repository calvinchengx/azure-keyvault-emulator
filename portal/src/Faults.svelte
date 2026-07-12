<script>
  import { api } from './api.js';

  let throttle = $state(1);
  let reject = $state(1);
  let msg = $state('');
  let error = $state('');

  async function inject(body, label) {
    error = '';
    msg = '';
    try {
      await api.post('/_emulator/faults', body);
      msg = label;
    } catch (e) {
      error = e.message;
    }
  }
</script>

<h1>Fault injection</h1>
<p class="muted">Make the emulator throttle (429 + Retry-After) or reject (500) the next N requests, so SDK retry behaviour is testable offline.</p>

{#if error}<p class="error">{error}</p>{/if}
{#if msg}<p style="color:var(--ok)">{msg}</p>{/if}

<div class="card" style="max-width:520px">
  <div class="field">
    <span class="lbl">Throttle next</span>
    <input type="number" min="0" bind:value={throttle} />
    <button class="btn" onclick={() => inject({ throttleNextRequests: Number(throttle) }, `Throttling the next ${throttle} request(s).`)}>Apply</button>
  </div>
  <div class="field">
    <span class="lbl">Reject next</span>
    <input type="number" min="0" bind:value={reject} />
    <button class="btn" onclick={() => inject({ rejectNextRequests: Number(reject) }, `Rejecting the next ${reject} request(s).`)}>Apply</button>
  </div>
  <div class="field">
    <span class="lbl"></span>
    <button class="btn btn-secondary" onclick={() => inject({ throttleNextRequests: 0, rejectNextRequests: 0 }, 'Faults cleared.')}>Clear all</button>
  </div>
</div>

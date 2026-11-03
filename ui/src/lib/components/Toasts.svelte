<script lang="ts">
  // What just happened, briefly. Problems are announced at once; the rest politely.
  import { model } from "../model.svelte";
</script>

<div class="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2" aria-live="polite">
  {#each model.toasts as toast (toast.id)}
    <div
      role={toast.ok ? "status" : "alert"}
      class="pointer-events-auto max-w-md rounded-lg px-3.5 py-2.5 text-sm shadow-card {toast.ok ? 'bg-primary text-on-primary' : 'bg-critical-strong text-on-critical'}"
    >
      {toast.text}
    </div>
  {/each}
</div>

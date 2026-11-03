<script lang="ts">
  // On or off. Sized in pixels: a rem is 13px here, and the thumb must travel
  // exactly the track's width less its own.
  import { Switch } from "bits-ui";

  type Props = { checked: boolean; onchange: (on: boolean) => void; label: string; disabled?: boolean };
  let { checked, onchange, label, disabled = false }: Props = $props();
</script>

<Switch.Root
  {checked}
  onCheckedChange={onchange}
  {disabled}
  aria-label={label}
  title={label}
  class="inline-flex h-[22px] w-[38px] shrink-0 items-center rounded-full bg-line-strong p-[3px] transition-colors data-[state=checked]:bg-primary data-[disabled]:opacity-45"
>
  <Switch.Thumb
    class="pointer-events-none block size-[16px] rounded-full bg-thumb shadow-thumb transition-transform data-[state=checked]:translate-x-[16px] data-[state=checked]:bg-on-primary motion-reduce:transition-none"
  />
</Switch.Root>

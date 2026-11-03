<script lang="ts">
  // The logo's three lenses (the menu bar glyph), in the current text colour.
  import svg from "../../../../assets/lenses.svg?raw";

  let { class: cls = "" }: { class?: string } = $props();

  // Each copy needs its own mask ids, or a second copy would use the first one's.
  const uid = `g${Math.random().toString(36).slice(2, 10)}`;
  const markup = svg
    .replace(/<!--[\s\S]*?-->/, "")
    .replaceAll('id="k', `id="${uid}k`)
    .replaceAll("url(#k", `url(#${uid}k`)
    .replace(/width="24" height="24"/, 'width="100%" height="100%" aria-hidden="true"');
</script>

<span class="inline-block shrink-0 {cls}">{@html markup}</span>

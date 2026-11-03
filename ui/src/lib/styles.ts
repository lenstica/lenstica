// Classes for parts drawn by Bits UI primitives (a select's list, the project
// picker's list), which take a class rather than one of our components.

/** A floating surface: a select's options, the project picker. */
export const popover =
  "z-50 rounded-lg border border-rim bg-panel/95 shadow-card outline-none backdrop-blur-xl";

/** One option in a floating list; highlighted by keyboard or pointer. */
export const option =
  "flex min-h-control cursor-default items-center gap-2 rounded-sm px-2.5 text-base outline-none data-[highlighted]:bg-glass-strong data-[selected]:bg-glass-strong";

/** The search field at the top of a floating list. */
export const listSearch =
  "h-control w-full border-b border-line bg-transparent px-3 text-base text-fg outline-none placeholder:text-faint";

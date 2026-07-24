// Tiny DOM helpers — the app is framework-free (SPEC: minimal deps). `el` builds an
// element with props + children; `field` builds a labelled input row.

type Child = Node | string;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v as string;
    else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
    } else {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (node as any)[k] = v;
    }
  }
  for (const c of children) node.append(c);
  return node;
}

export function field(labelText: string, input: HTMLElement, hint?: string): HTMLElement {
  const wrap = el("label", { class: "field" }, el("span", { class: "field-label", textContent: labelText }), input);
  if (hint) wrap.append(el("span", { class: "hint", textContent: hint }));
  return wrap;
}

export function input(value = "", placeholder = ""): HTMLInputElement {
  return el("input", { type: "text", value, placeholder, spellcheck: false });
}

export function textarea(value = "", rows = 4, placeholder = ""): HTMLTextAreaElement {
  return el("textarea", { value, rows, placeholder, spellcheck: false });
}

export function button(label: string, onClick: () => void, cls = "btn"): HTMLButtonElement {
  return el("button", { class: cls, textContent: label, onclick: onClick });
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

export function statusLine(container: HTMLElement, text: string, kind: "ok" | "err" | "info" = "info"): void {
  clear(container);
  container.append(el("div", { class: `status status-${kind}`, textContent: text }));
}

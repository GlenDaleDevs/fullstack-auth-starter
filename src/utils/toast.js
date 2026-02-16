let toasts = [];
let listeners = [];
let nextId = 0;
const MAX_TOASTS = 5;

export function showToast(message, type = "info", duration = null) {
  if (typeof message === "string" && toasts.some(t => t.message === message && t.type === type)) {
    return;
  }

  const toast = { id: nextId++, message, type };
  toasts = [...toasts, toast];

  if (toasts.length > MAX_TOASTS) {
    toasts = toasts.slice(-MAX_TOASTS);
  }

  listeners.forEach(fn => fn(toasts));

  const timeout = duration || (type === "error" ? 6000 : 4000);
  setTimeout(() => dismissToast(toast.id), timeout);

  return toast.id;
}

export function dismissToast(id) {
  toasts = toasts.filter(t => t.id !== id);
  listeners.forEach(fn => fn(toasts));
}

export function subscribe(listener) {
  listeners.push(listener);
  listener(toasts);
  return () => {
    listeners = listeners.filter(fn => fn !== listener);
  };
}

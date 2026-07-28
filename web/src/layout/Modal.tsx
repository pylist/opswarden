import {
  useLayoutEffect,
  useRef,
  type KeyboardEvent,
  type ReactNode,
} from "react";

type Props = {
  labelledBy: string;
  onClose: () => void;
  children: ReactNode;
  compact?: boolean;
};

const focusable =
  'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])';
const initialFocusable =
  'input:not([disabled]):not([readonly]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [href]';
const modalStack: symbol[] = [];

export function Modal({ labelledBy, onClose, children, compact }: Props) {
  const dialog = useRef<HTMLElement>(null);
  const token = useRef(Symbol("modal"));

  useLayoutEffect(() => {
    const trigger =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    modalStack.push(token.current);
    const target =
      dialog.current?.querySelector<HTMLElement>("[data-modal-initial-focus]") ??
      dialog.current?.querySelector<HTMLElement>("[autofocus]") ??
      dialog.current?.querySelector<HTMLElement>(initialFocusable);
    (target ?? dialog.current)?.focus();
    return () => {
      const index = modalStack.lastIndexOf(token.current);
      if (index >= 0) modalStack.splice(index, 1);
      if (trigger?.isConnected) trigger.focus();
    };
  }, []);

  function onKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key === "Escape") {
      if (modalStack.at(-1) !== token.current) return;
      event.preventDefault();
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== "Tab" || !dialog.current) return;
    const elements = [...dialog.current.querySelectorAll<HTMLElement>(focusable)]
      .filter((element) => !element.hidden);
    if (!elements.length) {
      event.preventDefault();
      dialog.current.focus();
      return;
    }
    const first = elements[0];
    const last = elements[elements.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="modal-layer">
      <section
        ref={dialog}
        className={compact ? "confirm-dialog" : "form-dialog"}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        {children}
      </section>
    </div>
  );
}

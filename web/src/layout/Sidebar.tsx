import { useEffect, useRef, type KeyboardEvent } from "react";

export type View =
  | "overview"
  | "credentials"
  | "assets"
  | "agents"
  | "audit"
  | "members"
  | "settings";

const navigation: Array<{ view: View; label: string; glyph: string }> = [
  { view: "overview", label: "概览", glyph: "⌂" },
  { view: "credentials", label: "凭据库", glyph: "◇" },
  { view: "assets", label: "资产", glyph: "□" },
  { view: "agents", label: "Agent", glyph: "◎" },
  { view: "audit", label: "审计日志", glyph: "≡" },
  { view: "members", label: "成员与权限", glyph: "○" },
  { view: "settings", label: "设置", glyph: "⚙" },
];

type SidebarProps = {
  current: View;
  open: boolean;
  mobile: boolean;
  onNavigate: (view: View) => void;
  onClose: () => void;
};

export function Sidebar({
  current,
  open,
  mobile,
  onNavigate,
  onClose,
}: SidebarProps) {
  const firstLink = useRef<HTMLAnchorElement>(null);
  const lastLink = useRef<HTMLAnchorElement>(null);

  useEffect(() => {
    if (open) {
      firstLink.current?.focus();
    }
  }, [open]);

  function trapFocus(event: KeyboardEvent<HTMLElement>) {
    if (!mobile || !open || event.key !== "Tab") return;
    if (event.shiftKey && document.activeElement === firstLink.current) {
      event.preventDefault();
      lastLink.current?.focus();
    } else if (!event.shiftKey && document.activeElement === lastLink.current) {
      event.preventDefault();
      firstLink.current?.focus();
    }
  }

  const hidden = mobile && !open;
  return (
    <>
      <nav
        className={`sidebar ${open ? "is-open" : ""}`}
        aria-label="主导航"
        aria-hidden={hidden ? true : undefined}
        inert={hidden ? true : undefined}
        onKeyDown={trapFocus}
      >
        <div className="sidebar-brand">
          <span className="brand-mark small" aria-hidden="true">O</span>
          <span>OpsWarden</span>
        </div>
        <div className="nav-items">
          {navigation.map((item, index) => (
            <a
              key={item.view}
              ref={
                index === 0
                  ? firstLink
                  : index === navigation.length - 1
                    ? lastLink
                    : undefined
              }
              href={`/?view=${item.view}`}
              tabIndex={hidden ? -1 : 0}
              aria-current={current === item.view ? "page" : undefined}
              onClick={(event) => {
                event.preventDefault();
                onNavigate(item.view);
                onClose();
              }}
            >
              <span className="nav-glyph" aria-hidden="true">{item.glyph}</span>
              {item.label}
            </a>
          ))}
        </div>
        <p className="sidebar-caption">内部管理服务</p>
      </nav>
      {open && (
        <button
          className="drawer-backdrop"
          type="button"
          aria-label="关闭导航"
          onClick={onClose}
        />
      )}
    </>
  );
}

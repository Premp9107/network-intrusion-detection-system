import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Activity,
  Bell,
  Info,
  LayoutDashboard,
  LineChart,
  Menu,
  ScanSearch,
  Shield,
  Upload,
  X,
} from "lucide-react";
import { api } from "../api";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/analyze", label: "Traffic Analysis", icon: Activity },
  { to: "/upload", label: "Upload Dataset", icon: Upload },
  { to: "/results", label: "Detection Results", icon: ScanSearch },
  { to: "/performance", label: "Model Performance", icon: LineChart },
  { to: "/alerts", label: "Alert History", icon: Bell },
  { to: "/about", label: "About Project", icon: Info },
];

const TITLES = {
  "/": "Dashboard",
  "/analyze": "Traffic Analysis",
  "/upload": "Upload Dataset",
  "/results": "Detection Results",
  "/performance": "Model Performance",
  "/alerts": "Alert History",
  "/about": "About Project",
};

function titleFor(pathname) {
  if (pathname.startsWith("/results")) return TITLES["/results"];
  return TITLES[pathname] || "Aegis NIDS";
}

export default function Layout() {
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState("");

  useEffect(() => {
    let active = true;
    api.health()
      .then((data) => active && setHealth(data))
      .catch((error) => active && setHealthError(error.message));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-ink text-slate-200">
      {open && <button className="fixed inset-0 z-20 bg-black/50 md:hidden" onClick={() => setOpen(false)} aria-label="Close menu" />}
      <aside className={`fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-line bg-[#0b1220] transition-transform ${open ? "translate-x-0" : "-translate-x-full"} md:translate-x-0`}>
        <div className="flex items-center gap-3 px-5 py-5">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-300">
            <Shield size={18} />
          </span>
          <div>
            <p className="text-sm font-semibold tracking-wide">Aegis NIDS</p>
            <p className="text-xs text-slate-400">Offline flow detection</p>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-2 text-sm ${
                    isActive ? "bg-cyan-400/10 text-cyan-200" : "text-slate-300 hover:bg-white/5"
                  }`
                }
              >
                <Icon size={16} />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
        <p className="px-5 py-4 text-xs leading-5 text-slate-500">CSV classification only. No live packet capture.</p>
      </aside>
      <div className="md:pl-64">
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-line bg-[#070b14]/90 px-4 py-3 backdrop-blur md:px-6">
          <div className="flex items-center gap-3">
            <button className="rounded-md border border-line p-2 md:hidden" onClick={() => setOpen(true)} aria-label="Open menu">
              {open ? <X size={16} /> : <Menu size={16} />}
            </button>
            <h1 className="text-base font-medium text-slate-100">{titleFor(location.pathname)}</h1>
          </div>
          <div className="text-right text-xs">
            {health ? (
              <p className="text-emerald-300">Model loaded · {health.model_name.replaceAll("_", " ")}</p>
            ) : (
              <p className="text-amber-200">{healthError || "Checking API…"}</p>
            )}
            <p className="text-slate-500">Offline CSV mode</p>
          </div>
        </header>
        <main className="mx-auto max-w-7xl space-y-4 p-4 md:p-6">
          <Outlet context={{ health }} />
        </main>
      </div>
    </div>
  );
}

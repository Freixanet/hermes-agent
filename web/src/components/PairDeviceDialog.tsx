import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import * as QRCode from "qrcode";
import { Badge } from "@nous-research/ui/ui/components/badge";
import { Button } from "@nous-research/ui/ui/components/button";
import { Spinner } from "@nous-research/ui/ui/components/spinner";
import { Copy, RefreshCw } from "lucide-react";
import {
  DASHBOARD_MODAL_BACKDROP,
  DASHBOARD_MODAL_PANEL,
} from "@/lib/dashboard-modal-shell";
import { copyTextToClipboard } from "@/lib/clipboard";
import { api, type AlicePairingSession } from "@/lib/api";
import { cn, themedBody } from "@/lib/utils";

/**
 * "Connect Alice": mints one Alice QR-pairing offer and shows it as a QR
 * code for the iPhone Camera. The phone claims the token once — after that
 * (or after the TTL) the code is dead and a fresh one costs one click.
 */
export function PairDeviceDialog({
  onClose,
  open,
}: {
  onClose: () => void;
  open: boolean;
}) {
  const [session, setSession] = useState<AlicePairingSession | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [minting, setMinting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [, setTick] = useState(0);
  const sessionRef = useRef(session);
  sessionRef.current = session;

  const mint = useCallback(async () => {
    setMinting(true);
    setError(null);
    setCopied(false);
    try {
      const next = await api.startAlicePairing();
      setSession(next);
      setQrDataUrl(
        await QRCode.toDataURL(next.payload, {
          errorCorrectionLevel: "M",
          margin: 2,
          width: 320,
        }),
      );
    } catch (e) {
      setSession(null);
      setQrDataUrl(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setMinting(false);
    }
  }, []);

  useEffect(() => {
    if (open) void mint();
  }, [open, mint]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, onClose]);

  // 1 Hz re-render drives the expiry countdown badge.
  useEffect(() => {
    if (!open || !session) return;
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, [open, session]);

  const expiresIn = useMemo(() => {
    if (!session) return "";
    const ms = Date.parse(session.expires_at) - Date.now();
    if (!Number.isFinite(ms) || ms <= 0) return "expired";
    const seconds = Math.ceil(ms / 1000);
    return `${Math.floor(seconds / 60)}:${(seconds % 60).toString().padStart(2, "0")}`;
  }, [session]);

  if (!open) return null;

  const handleCopy = async () => {
    if (!session) return;
    if (await copyTextToClipboard(session.payload)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="pair-device-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className={DASHBOARD_MODAL_BACKDROP}
    >
      <div
        className={cn(themedBody, DASHBOARD_MODAL_PANEL, "max-w-md")}
      >
        <div className="flex items-start justify-between gap-3 border-b border-border p-4">
          <div className="flex flex-col gap-1">
            <h2
              id="pair-device-title"
              className="font-mondwest text-display text-base tracking-wider"
            >
              Connect Alice
            </h2>
            <p className="text-xs text-muted-foreground">
              Pair the Alice iPhone app with this Hermes
            </p>
          </div>
          {session && (
            <Badge tone={expiresIn === "expired" ? "destructive" : "outline"}>
              {expiresIn === "expired" ? "expired" : `expires ${expiresIn}`}
            </Badge>
          )}
        </div>

        <div className="flex flex-col items-center gap-4 p-6">
          {minting && <Spinner className="text-2xl text-primary" />}

          {error && !minting && (
            <div className="flex flex-col items-center gap-3 text-center">
              <p className="text-sm text-destructive">{error}</p>
              <Button size="sm" onClick={() => void mint()}>
                Try again
              </Button>
            </div>
          )}

          {session && qrDataUrl && !minting && (
            <>
              <img
                src={qrDataUrl}
                alt="Alice pairing QR code"
                className="h-64 w-64 rounded-lg bg-white p-2"
              />
              <ol className="list-decimal space-y-0.5 pl-5 text-xs text-muted-foreground">
                <li>Install Alice on the iPhone if it is not installed.</li>
                <li>Point the iPhone Camera app at this code.</li>
                <li>Open the Alice link and confirm the pairing.</li>
              </ol>
              <p className="max-w-full truncate text-center font-mono text-[11px] text-muted-foreground">
                {session.payload}
              </p>
              <div className="flex items-center gap-2">
                <Button size="sm" outlined onClick={() => void handleCopy()}>
                  <Copy className="h-3.5 w-3.5" />
                  {copied ? "Copied" : "Copy link"}
                </Button>
                <Button
                  size="sm"
                  outlined
                  onClick={() => void mint()}
                  disabled={minting}
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  New code
                </Button>
              </div>
              <p className="text-center text-[11px] text-muted-foreground">
                The code works once and stops being served the moment a device
                claims it. Session ref: {sessionRef.current?.profile}
              </p>
            </>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-border p-3">
          <Button type="button" outlined onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

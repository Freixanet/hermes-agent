import { useCallback, useEffect, useRef, useState } from "react";
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
 * "Connect Alice": mint one short-lived, one-time Alice v1 pairing offer and
 * render it as a QR. The QR contains only the temporary claim bearer; Hermes'
 * long-lived gateway/dashboard credentials are returned only after the claim.
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
  const mintGeneration = useRef(0);

  const mint = useCallback(async () => {
    const generation = ++mintGeneration.current;
    setMinting(true);
    setError(null);
    setCopied(false);
    try {
      const next = await api.startAlicePairing();
      const dataUrl = await QRCode.toDataURL(next.payload, {
        errorCorrectionLevel: "M",
        margin: 2,
        width: 320,
      });
      if (generation !== mintGeneration.current) return;
      setSession(next);
      setQrDataUrl(dataUrl);
    } catch (e) {
      if (generation !== mintGeneration.current) return;
      setSession(null);
      setQrDataUrl(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (generation === mintGeneration.current) setMinting(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      void mint();
    } else {
      // Ignore an in-flight response from a dialog that has already closed.
      mintGeneration.current += 1;
    }
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

  // Drive the expiry text once per second. The value is intentionally not
  // memoized: each tick must recompute against Date.now().
  useEffect(() => {
    if (!open || !session) return;
    const id = setInterval(() => setTick((tick) => tick + 1), 1000);
    return () => clearInterval(id);
  }, [open, session]);

  if (!open) return null;

  const expiresIn = (() => {
    if (!session) return "";
    const ms = Date.parse(session.expires_at) - Date.now();
    if (!Number.isFinite(ms) || ms <= 0) return "expired";
    const seconds = Math.ceil(ms / 1000);
    return `${Math.floor(seconds / 60)}:${(seconds % 60).toString().padStart(2, "0")}`;
  })();
  const expired = expiresIn === "expired";

  const handleCopy = async () => {
    if (!session || expired) return;
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
            <Badge tone={expired ? "destructive" : "outline"}>
              {expired ? "expired" : `expires ${expiresIn}`}
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
                <li>Open Alice on the iPhone.</li>
                <li>Open Connect and tap Scan pairing QR.</li>
                <li>Scan this code and confirm the pairing.</li>
              </ol>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  outlined
                  onClick={() => void handleCopy()}
                  disabled={expired}
                >
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
                One-time code for{" "}
                {session.profile_display_name || session.profile}. Creating a
                new code invalidates the previous one.
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

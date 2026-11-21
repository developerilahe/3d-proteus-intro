import { useEffect } from 'react';

export const TAKEDOWN_CHANNELS = [
  'Domain Registrar',
  'Hosting Provider',
  'Google Safe Browsing',
  'Microsoft Defender SmartScreen',
  'APWG',
  'National CERT / CSIRT',
];

interface TakedownModalProps {
  open: boolean;
  domain: string | null;
  channel: string;
  reportText: string;
  copiedNote: boolean;
  onClose: () => void;
  onChannelChange: (channel: string) => void;
  onCopy: () => void;
  onDownload: () => void;
}

export function TakedownModal({
  open,
  domain,
  channel,
  reportText,
  copiedNote,
  onClose,
  onChannelChange,
  onCopy,
  onDownload,
}: TakedownModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      id="takedown-modal"
      className="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="takedown-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-content">
        <div className="modal-header">
          <div>
            <h2 id="takedown-modal-title">Takedown Report</h2>
            {domain && (
              <div
                style={{
                  fontFamily: 'var(--font-data)',
                  fontSize: 12,
                  color: 'var(--accent-text)',
                  marginTop: 2,
                }}
              >
                {domain}
              </div>
            )}
          </div>
          <button
            type="button"
            className="btn-close"
            aria-label="Close modal"
            onClick={onClose}
          >
            &times;
          </button>
        </div>

        <div
          style={{
            padding: '12px 24px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            flexWrap: 'wrap',
          }}
        >
          <label htmlFor="takedown-channel" style={{ color: 'var(--text-dim)', fontSize: 12 }}>
            Route to:
          </label>
          <select
            id="takedown-channel"
            value={channel}
            onChange={(e) => onChannelChange(e.target.value)}
          >
            {TAKEDOWN_CHANNELS.map((ch) => (
              <option key={ch} value={ch}>
                {ch}
              </option>
            ))}
          </select>
        </div>

        <pre id="modal-report-text" className="modal-body">
          {reportText || 'Loading report…'}
        </pre>

        <div className="modal-actions">
          <span
            aria-live="polite"
            style={{
              color: 'var(--low)',
              fontSize: 11,
              marginRight: 'auto',
              fontFamily: 'var(--font-data)',
            }}
          >
            {copiedNote ? 'Copied to clipboard.' : ''}
          </span>
          <button type="button" className="btn-outline" onClick={onCopy}>
            Copy
          </button>
          <button type="button" className="wb-btn" onClick={onDownload}>
            Download .TXT
          </button>
        </div>
      </div>
    </div>
  );
}

import React, { useRef, useEffect, KeyboardEvent, ClipboardEvent, ChangeEvent } from 'react';

interface OTPInputProps {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
}

export default function OTPInput({
  value,
  onChange,
  disabled = false,
  autoFocus = true,
}: OTPInputProps) {
  const inputRefs = useRef<Array<HTMLInputElement | null>>([]);

  // Always produce exactly 6 elements — padEnd(6,'') is broken (empty padString returns input unchanged)
  const digits = Array.from({ length: 6 }, (_, i) => value[i] ?? '');

  // Auto-focus first empty cell (or last filled) when component mounts or becomes enabled
  useEffect(() => {
    if (!autoFocus || disabled) return;
    const firstEmpty = digits.findIndex((d) => d === '');
    const target = firstEmpty === -1 ? 5 : firstEmpty;
    inputRefs.current[target]?.focus();
  }, [autoFocus, disabled]); // eslint-disable-line react-hooks/exhaustive-deps

  const updateDigit = (index: number, digit: string) => {
    const next = Array.from({ length: 6 }, (_, i) => digits[i]);
    next[index] = digit;
    onChange(next.join('').replace(/[^0-9]/g, ''));
  };

  const handleChange = (index: number, e: ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value.replace(/[^0-9]/g, '');
    if (!v) {
      updateDigit(index, '');
      return;
    }
    updateDigit(index, v[v.length - 1]);
    if (index < 5) inputRefs.current[index + 1]?.focus();
  };

  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') {
      if (digits[index]) {
        updateDigit(index, '');
      } else if (index > 0) {
        inputRefs.current[index - 1]?.focus();
        updateDigit(index - 1, '');
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowRight' && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const text = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 6);
    if (text) {
      onChange(text);
      const lastFilledIdx = Math.min(text.length, 5);
      inputRefs.current[lastFilledIdx]?.focus();
    }
  };

  return (
    <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
      {digits.map((digit, i) => (
        <input
          key={i}
          ref={(el) => { inputRefs.current[i] = el; }}
          type="text"
          inputMode="numeric"
          maxLength={1}
          value={digit}
          disabled={disabled}
          onChange={(e) => handleChange(i, e)}
          onKeyDown={(e) => handleKeyDown(i, e)}
          onPaste={i === 0 ? handlePaste : undefined}
          onFocus={(e) => e.target.select()}
          style={{
            width: 48,
            height: 56,
            textAlign: 'center',
            fontSize: 24,
            fontFamily: "'Fira Code', 'Cascadia Code', 'Courier New', monospace",
            fontWeight: 700,
            background: disabled ? 'rgba(0,20,40,0.5)' : 'rgba(0, 20, 40, 0.9)',
            color: digit ? '#00d4ff' : '#6b8fa3',
            border: digit
              ? '1px solid rgba(0, 212, 255, 0.8)'
              : '1px solid rgba(0, 212, 255, 0.25)',
            borderRadius: 8,
            outline: 'none',
            cursor: disabled ? 'not-allowed' : 'text',
            transition: 'all 0.15s ease',
            boxShadow: digit
              ? '0 0 12px rgba(0,212,255,0.4), inset 0 0 8px rgba(0,212,255,0.05)'
              : 'none',
          }}
        />
      ))}
    </div>
  );
}

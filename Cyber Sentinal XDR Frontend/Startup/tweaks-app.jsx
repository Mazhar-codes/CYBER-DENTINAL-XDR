/* global React, ReactDOM, TweaksPanel, TweakSection, TweakRadio, TweakSlider, TweakToggle, TweakColor, TweakButton, useTweaks */

const { useEffect } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "cyan",
  "intensity": 1,
  "speed": 1,
  "showTerminal": true
}/*EDITMODE-END*/;

function CinematicTweaks() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);

  useEffect(() => {
    if (window.applyTweaks) window.applyTweaks(t);
  }, [t]);

  return (
    <TweaksPanel title="Cinematic Tweaks">
      <TweakSection title="Accent">
        <TweakRadio
          label="Color signature"
          value={t.accent}
          onChange={v => setTweak('accent', v)}
          options={[
            { value: 'cyan',   label: 'Cyan' },
            { value: 'blue',   label: 'Blue' },
            { value: 'violet', label: 'Violet' },
            { value: 'green',  label: 'Green' },
          ]}
        />
      </TweakSection>

      <TweakSection title="Motion">
        <TweakSlider
          label="Playback speed"
          value={t.speed}
          min={0.5} max={2} step={0.1}
          onChange={v => setTweak('speed', v)}
          format={v => v.toFixed(1) + 'x'}
        />
        <TweakSlider
          label="Particle intensity"
          value={t.intensity}
          min={0.4} max={1.6} step={0.1}
          onChange={v => setTweak('intensity', v)}
          format={v => v.toFixed(1) + 'x'}
        />
      </TweakSection>

      <TweakSection title="Scenes">
        <TweakToggle
          label="Boot terminal"
          value={t.showTerminal}
          onChange={v => setTweak('showTerminal', v)}
        />
        <TweakButton
          label="↻ Replay cinematic"
          onClick={() => window.cinematic && window.cinematic.replay()}
        />
        <TweakButton
          label="⏭ Skip to login"
          onClick={() => window.cinematic && window.cinematic.skip()}
        />
      </TweakSection>
    </TweaksPanel>
  );
}

const host = document.getElementById('tweaks-host');
if (host) ReactDOM.createRoot(host).render(<CinematicTweaks />);

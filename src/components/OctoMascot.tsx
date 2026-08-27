import React, { useState } from 'react';

interface OctoMascotProps {
  size?: number | string;
  variant?: 'silhouette' | 'cyber' | 'badge' | 'hero';
  className?: string;
  showDialogue?: boolean;
  dialogueText?: string;
  interactive?: boolean;
}

export const OctoMascot: React.FC<OctoMascotProps> = ({
  size = 40,
  variant = 'badge',
  className = '',
  showDialogue = false,
  dialogueText = 'OctoLAN probes all 8 network tentacles across your broadcast domain!',
  interactive = true
}) => {
  const [isWaving, setIsWaving] = useState(false);
  const [dialogueOpen, setDialogueOpen] = useState(showDialogue);

  const tips = [
    'Tentacle 1: Capturing NetFlow v5 UDP packets on port 2055!',
    'Tentacle 2: Monitoring L2 Broadcast & Multicast PPS rates.',
    'Tentacle 3: Checking Spanning Tree BPDU loops on access ports.',
    'Tentacle 4: Sniffing IEEE 802.1Q tagged VLAN trunks.',
    'Tentacle 5: Fingerprinting OS stacks via IP TTL and TCP Window size.',
    'Tentacle 6: Passive zero-footprint DHCP Option 12 hostname extraction.',
    'Tentacle 7: Inspecting LLDP switch chassis and port ID advertisements.',
    'Tentacle 8: Zero-dependency native POSIX C99 raw socket engine ready!'
  ];

  const handleInteraction = () => {
    if (!interactive) return;
    setIsWaving(true);
    setDialogueOpen(prev => !prev);
    setTimeout(() => setIsWaving(false), 1200);
  };

  if (variant === 'badge') {
    return (
      <div 
        className={`relative inline-flex items-center justify-center cursor-pointer transition transform hover:scale-105 ${className}`}
        onClick={handleInteraction}
        title="Inky: OctoLAN Network Mascot - Click to interact"
      >
        <svg 
          width={size} 
          height={size} 
          viewBox="0 0 100 100" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
          className={isWaving ? 'animate-bounce' : ''}
        >
          {/* Vibrant Green Background Badge */}
          <rect width="100" height="100" rx="22" fill="#238636" stroke="#2ea043" strokeWidth="2" />
          <circle cx="50" cy="50" r="44" fill="#2ea043" />
          <circle cx="50" cy="50" r="40" fill="none" stroke="#3fb950" strokeWidth="1" strokeDasharray="3 2" opacity="0.7" />

          {/* Inky: Monochrome Black Cartoon Octopus */}
          <g fill="#0d1117" stroke="#0d1117" strokeLinejoin="round" strokeLinecap="round">
            {/* 8 Tentacles */}
            <path d="M 37 56 C 26 52, 14 43, 11 32 C 10 27, 16 24, 20 28 C 24 33, 28 42, 38 51 Z" strokeWidth="1" />
            <path d="M 34 61 C 21 60, 9 53, 6 62 C 5 68, 11 71, 19 69 C 26 68, 32 64, 37 62 Z" strokeWidth="1" />
            <path d="M 38 67 C 29 73, 16 82, 19 88 C 22 93, 29 90, 32 84 C 35 78, 39 72, 41 70 Z" strokeWidth="1" />
            <path d="M 43 70 C 39 79, 36 89, 42 93 C 46 95, 49 90, 49 83 C 49 76, 47 71, 46 70 Z" strokeWidth="1" />
            <path d="M 54 70 C 53 71, 51 76, 51 83 C 51 90, 54 95, 58 93 C 64 89, 61 79, 57 70 Z" strokeWidth="1" />
            <path d="M 59 70 C 61 72, 65 78, 68 84 C 71 90, 78 93, 81 88 C 84 82, 71 73, 62 67 Z" strokeWidth="1" />
            <path d="M 63 62 C 68 64, 74 68, 81 69 C 89 71, 95 68, 94 62 C 91 53, 79 60, 66 61 Z" strokeWidth="1" />
            <path d="M 62 51 C 72 42, 76 33, 80 28 C 84 24, 90 27, 89 32 C 86 43, 74 52, 63 56 Z" strokeWidth="1" />

            {/* Smooth Cartoon Dome Head */}
            <path d="M 31 53 C 28 37, 34 18, 50 18 C 66 18, 72 37, 69 53 C 68 63, 62 70, 50 70 C 38 70, 32 63, 31 53 Z" strokeWidth="1" />
          </g>

          {/* Big White Cartoon Eyes */}
          <ellipse cx="42" cy="45" rx="5.5" ry="6.5" fill="#ffffff" />
          <ellipse cx="58" cy="45" rx="5.5" ry="6.5" fill="#ffffff" />

          {/* Black Pupils */}
          <ellipse cx="43" cy="45.5" rx="3.2" ry="4" fill="#0d1117" />
          <ellipse cx="57" cy="45.5" rx="3.2" ry="4" fill="#0d1117" />

          {/* Catchlight Highlights */}
          <circle cx="41.5" cy="43.5" r="1.3" fill="#ffffff" />
          <circle cx="55.5" cy="43.5" r="1.3" fill="#ffffff" />
          <circle cx="44" cy="47" r="0.6" fill="#ffffff" />
          <circle cx="58" cy="47" r="0.6" fill="#ffffff" />

          {/* Cute White Smile */}
          <path d="M 47 56 Q 50 59.5 53 56" fill="none" stroke="#ffffff" strokeWidth="1.2" strokeLinecap="round" />
        </svg>
      </div>
    );
  }

  return (
    <div className={`relative flex items-center gap-3 ${className}`}>
      {/* Octopus Cartoon Mascot Graphic */}
      <div 
        className="relative group cursor-pointer flex-shrink-0"
        onClick={handleInteraction}
      >
        <div className={`w-14 h-14 sm:w-16 sm:h-16 rounded-2xl bg-[#238636] border border-[#2ea043] p-1.5 flex items-center justify-center shadow-lg transition-transform ${isWaving ? 'scale-110 rotate-3' : 'hover:scale-105'}`}>
          <svg viewBox="0 0 400 400" className="w-full h-full">
            {/* Background Green Ring */}
            <circle cx="200" cy="200" r="175" fill="#2ea043" />
            <circle cx="200" cy="200" r="162" fill="none" stroke="#3fb950" strokeWidth="4" opacity="0.6" strokeDasharray="12 8" />

            {/* Inky Monochrome Body */}
            <g fill="#0d1117" stroke="#0d1117" strokeLinejoin="round" strokeLinecap="round">
              <path d="M 145 225 C 105 210, 55 175, 45 130 C 40 108, 65 98, 80 115 C 96 132, 112 170, 150 205 Z" strokeWidth="4" />
              <path d="M 135 245 C 85 240, 35 215, 25 250 C 20 272, 45 285, 75 278 C 105 272, 128 258, 146 250 Z" strokeWidth="4" />
              <path d="M 150 270 C 115 292, 65 328, 78 355 C 88 375, 118 360, 128 338 C 142 312, 156 290, 166 280 Z" strokeWidth="4" />
              <path d="M 172 282 C 156 316, 146 358, 168 372 C 184 382, 196 360, 196 332 C 196 306, 190 286, 186 282 Z" strokeWidth="4" />
              <path d="M 214 282 C 210 286, 204 306, 204 332 C 204 360, 216 382, 232 372 C 254 358, 244 316, 228 282 Z" strokeWidth="4" />
              <path d="M 234 280 C 244 290, 258 312, 272 338 C 282 360, 312 375, 322 355 C 335 328, 285 292, 250 270 Z" strokeWidth="4" />
              <path d="M 254 250 C 272 258, 295 272, 325 278 C 355 285, 380 272, 375 250 C 365 215, 315 240, 265 245 Z" strokeWidth="4" />
              <path d="M 250 205 C 288 170, 304 132, 320 115 C 335 98, 360 108, 355 130 C 345 175, 295 210, 255 225 Z" strokeWidth="4" />
              <path d="M 125 215 C 112 150, 135 75, 200 75 C 265 75, 288 150, 275 215 C 270 252, 248 282, 200 282 C 152 282, 130 252, 125 215 Z" strokeWidth="4" />
            </g>

            {/* Eyes */}
            <ellipse cx="166" cy="178" rx="22" ry="26" fill="#ffffff" />
            <ellipse cx="234" cy="178" rx="22" ry="26" fill="#ffffff" />
            <ellipse cx="170" cy="180" rx="13" ry="16" fill="#0d1117" />
            <ellipse cx="230" cy="180" rx="13" ry="16" fill="#0d1117" />
            <circle cx="164" cy="172" r="5.5" fill="#ffffff" />
            <circle cx="224" cy="172" r="5.5" fill="#ffffff" />
            <circle cx="174" cy="186" r="2.5" fill="#ffffff" />
            <circle cx="234" cy="186" r="2.5" fill="#ffffff" />

            {/* Smile */}
            <path d="M 188 222 Q 200 236 212 222" fill="none" stroke="#ffffff" strokeWidth="5" strokeLinecap="round" />

            {/* Blush */}
            <ellipse cx="140" cy="208" rx="8" ry="4.5" fill="#3fb950" opacity="0.8" />
            <ellipse cx="260" cy="208" rx="8" ry="4.5" fill="#3fb950" opacity="0.8" />
          </svg>
        </div>

        {/* Pulse Indicator */}
        <span className="absolute -top-1 -right-1 flex h-3 w-3">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#7ee787] opacity-75"></span>
          <span className="relative inline-flex rounded-full h-3 w-3 bg-[#238636] border border-[#0d1117]"></span>
        </span>
      </div>

      {/* Dialogue / Speech Bubble */}
      {dialogueOpen && (
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-3 text-xs text-[#c9d1d9] shadow-md max-w-sm relative">
          <div className="flex items-center justify-between gap-2 mb-1 border-b border-[#21262d] pb-1">
            <span className="font-bold text-[#7ee787] text-[11px] flex items-center gap-1.5">
              🐙 Inky — OctoLAN Mascot
            </span>
            <span className="text-[10px] text-[#8b949e] font-mono">8 Tentacles Active</span>
          </div>
          <p className="text-[11px] text-[#c9d1d9] leading-relaxed">
            {dialogueText}
          </p>
          <div className="mt-1.5 flex items-center justify-between text-[10px] text-[#8b949e]">
            <span>Click mascot to cycle tips</span>
            <button 
              onClick={(e) => {
                e.stopPropagation();
                const randomTip = tips[Math.floor(Math.random() * tips.length)];
                dialogueText = randomTip;
                handleInteraction();
              }}
              className="text-[#58a6ff] hover:underline"
            >
              Next Tip &rarr;
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

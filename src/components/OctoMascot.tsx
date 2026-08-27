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
        title="Inky: OctoLAN Network Security Icon - Click to interact"
      >
        <svg 
          width={size} 
          height={size} 
          viewBox="0 0 100 100" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
          className={isWaving ? 'animate-pulse' : ''}
        >
          {/* Professional Green Background Badge */}
          <rect width="100" height="100" rx="22" fill="#238636" stroke="#2ea043" strokeWidth="2" />
          <circle cx="50" cy="50" r="42" fill="#2ea043" />
          <circle cx="50" cy="50" r="39" fill="none" stroke="#3fb950" strokeWidth="0.8" strokeDasharray="3 2" opacity="0.6" />

          {/* Inky: Sleek Professional Monochrome Octopus Icon */}
          <g fill="#0d1117">
            {/* Sleek Dome Mantle */}
            <path d="M 33 49 C 33 28, 40 20, 50 20 C 60 20, 67 28, 67 49 C 67 56, 63 61, 50 61 C 37 61, 33 56, 33 49 Z" />

            {/* 8 Cleanly Sculpted Tentacles */}
            <path d="M 36.5 49 C 27.5 46, 16 40, 13 30 C 12 26, 16.5 24, 19 27 C 22.5 32, 29 41, 39 46 Z" />
            <path d="M 63.5 49 C 72.5 46, 84 40, 87 30 C 88 26, 83.5 24, 81 27 C 77.5 32, 71 41, 61 46 Z" />

            <path d="M 34.5 54 C 23 54, 12 50, 9 59 C 7.5 63, 13 66, 19 64.5 C 27 62, 33 58, 37.5 55.5 Z" />
            <path d="M 65.5 54 C 77 54, 88 50, 91 59 C 92.5 63, 87 66, 81 64.5 C 73 62, 67 58, 62.5 55.5 Z" />

            <path d="M 38 59 C 29.5 65, 18.5 74, 21.5 82 C 23.5 86.5, 30 83.5, 33 78 C 36.5 71.5, 40 65, 43 61.5 Z" />
            <path d="M 62 59 C 70.5 65, 81.5 74, 78.5 82 C 76.5 86.5, 70 83.5, 67 78 C 63.5 71.5, 60 65, 57 61.5 Z" />

            <path d="M 43.5 61.5 C 39.5 69, 36.5 79.5, 41.5 84 C 45.5 87, 48.5 82, 48.5 75 C 48.5 68.5, 47 63.5, 46.5 62 Z" />
            <path d="M 56.5 61.5 C 60.5 69, 63.5 79.5, 58.5 84 C 54.5 87, 51.5 82, 51.5 75 C 51.5 68.5, 53 63.5, 53.5 62 Z" />
          </g>

          {/* Minimalist Tech Aperture Accent */}
          <path d="M 43 41 C 45.5 40, 47.5 39.5, 50 39.5 C 52.5 39.5, 54.5 40, 57 41" stroke="#2ea043" strokeWidth="1.2" strokeLinecap="round" />
          <circle cx="50" cy="45" r="1.2" fill="#2ea043" />
        </svg>
      </div>
    );
  }

  return (
    <div className={`relative flex items-center gap-3 ${className}`}>
      {/* Octopus Professional Icon Graphic */}
      <div 
        className="relative group cursor-pointer flex-shrink-0"
        onClick={handleInteraction}
      >
        <div className={`w-14 h-14 sm:w-16 sm:h-16 rounded-2xl bg-[#238636] border border-[#2ea043] p-1.5 flex items-center justify-center shadow-lg transition-transform ${isWaving ? 'scale-105' : 'hover:scale-105'}`}>
          <svg viewBox="0 0 400 400" className="w-full h-full">
            {/* Background Green Ring */}
            <circle cx="200" cy="200" r="170" fill="#2ea043" />
            <circle cx="200" cy="200" r="156" fill="none" stroke="#3fb950" strokeWidth="3" opacity="0.5" strokeDasharray="10 6" />

            {/* Inky Monochrome Professional Body */}
            <g fill="#0d1117">
              <path d="M 132 195 C 132 110, 160 80, 200 80 C 240 80, 268 110, 268 195 C 268 226, 252 245, 200 245 C 148 245, 132 226, 132 195 Z" />
              
              {/* 8 Tentacles */}
              <path d="M 146 195 C 110 185, 65 160, 52 118 C 48 104, 66 94, 76 108 C 90 128, 115 165, 155 185 Z" />
              <path d="M 254 195 C 290 185, 335 160, 348 118 C 352 104, 334 94, 324 108 C 310 128, 285 165, 245 185 Z" />

              <path d="M 138 215 C 92 215, 48 200, 36 235 C 30 252, 52 265, 76 258 C 108 248, 132 232, 150 222 Z" />
              <path d="M 262 215 C 308 215, 352 200, 364 235 C 370 252, 348 265, 324 258 C 292 248, 268 232, 250 222 Z" />

              <path d="M 152 236 C 118 260, 74 298, 86 328 C 94 346, 120 334, 132 312 C 146 286, 160 260, 172 246 Z" />
              <path d="M 248 236 C 282 260, 326 298, 314 328 C 306 346, 280 334, 268 312 C 254 286, 240 260, 228 246 Z" />

              <path d="M 174 246 C 158 276, 146 318, 166 335 C 182 348, 194 328, 194 300 C 194 274, 188 254, 186 248 Z" />
              <path d="M 226 246 C 242 276, 254 318, 234 335 C 218 348, 206 328, 206 300 C 206 274, 212 254, 214 248 Z" />
            </g>

            {/* Sleek Tech Negative-Space Visor / Aperture Line */}
            <path d="M 172 165 C 182 162, 191 160, 200 160 C 209 160, 218 162, 228 165" fill="none" stroke="#2ea043" strokeWidth="5" strokeLinecap="round" />
            <circle cx="200" cy="180" r="4.5" fill="#2ea043" />
          </svg>
        </div>

        {/* Status Indicator */}
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

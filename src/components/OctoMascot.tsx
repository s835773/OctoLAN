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
        title="OctoLAN Network Mascot - Click to interact"
      >
        <svg 
          width={size} 
          height={size} 
          viewBox="0 0 100 100" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
          className={isWaving ? 'animate-bounce' : ''}
        >
          {/* Badge Background Circle */}
          <rect width="100" height="100" rx="24" fill="#010409" stroke="#30363d" strokeWidth="4" />
          
          {/* Subtle Cyber Grid */}
          <path d="M 50 15 L 50 85 M 15 50 L 85 50" stroke="#238636" strokeWidth="1.5" strokeDasharray="3 3" opacity="0.4" />

          {/* Cartoon Octopus Silhouette & Body */}
          <g fill="#238636" stroke="#0d1117" strokeWidth="1.5">
            {/* Left Tentacles */}
            <path d="M 38 60 C 22 55, 12 40, 16 30 C 20 25, 26 30, 28 36 C 30 45, 34 52, 40 58 Z" />
            <path d="M 36 68 C 18 70, 8 62, 10 74 C 12 80, 22 78, 30 74 Z" />
            <path d="M 40 76 C 28 85, 20 92, 28 96 C 35 94, 38 85, 44 78 Z" />
            
            {/* Right Tentacles */}
            <path d="M 62 60 C 78 55, 88 40, 84 30 C 80 25, 74 30, 72 36 C 70 45, 66 52, 60 58 Z" />
            <path d="M 64 68 C 82 70, 92 62, 90 74 C 88 80, 78 78, 70 74 Z" />
            <path d="M 60 76 C 72 85, 80 92, 72 96 C 65 94, 62 85, 56 78 Z" />

            {/* Bottom Center Tentacles */}
            <path d="M 46 80 C 44 88, 42 94, 48 97 C 52 95, 50 88, 49 80 Z" />
            <path d="M 54 80 C 56 88, 58 94, 52 97 C 48 95, 50 88, 51 80 Z" />

            {/* Dome Head */}
            <path d="M 32 55 C 30 35, 36 20, 50 20 C 64 20, 70 35, 68 55 C 66 65, 60 72, 50 72 C 40 72, 34 65, 32 55 Z" fill="#58a6ff" />
          </g>

          {/* Big Cute Expressive Eyes */}
          <ellipse cx="42" cy="48" rx="6" ry="8" fill="#ffffff" />
          <ellipse cx="58" cy="48" rx="6" ry="8" fill="#ffffff" />
          <circle cx="43" cy="49" r="4" fill="#0d1117" />
          <circle cx="57" cy="49" r="4" fill="#0d1117" />
          <circle cx="41" cy="46" r="1.5" fill="#7ee787" />
          <circle cx="55" cy="46" r="1.5" fill="#7ee787" />

          {/* Cute Smile */}
          <path d="M 47 58 Q 50 62 53 58" fill="none" stroke="#0d1117" strokeWidth="2" strokeLinecap="round" />

          {/* Glowing Headband Status LED */}
          <rect x="38" y="26" width="24" height="6" rx="2" fill="#010409" stroke="#7ee787" strokeWidth="1" />
          <circle cx="43" cy="29" r="1.5" fill="#7ee787" />
          <circle cx="50" cy="29" r="1.5" fill="#58a6ff" />
          <circle cx="57" cy="29" r="1.5" fill="#7ee787" />
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
        <div className={`w-14 h-14 sm:w-16 sm:h-16 rounded-2xl bg-[#010409] border border-[#30363d] p-1.5 flex items-center justify-center shadow-lg transition-transform ${isWaving ? 'scale-110 rotate-3' : 'hover:scale-105'}`}>
          <svg viewBox="0 0 400 400" className="w-full h-full">
            <defs>
              <linearGradient id="mascotGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#58a6ff" />
                <stop offset="50%" stopColor="#238636" />
                <stop offset="100%" stopColor="#1f6feb" />
              </linearGradient>
            </defs>

            {/* Background aura */}
            <circle cx="200" cy="200" r="180" fill="#161b22" stroke="#30363d" strokeWidth="4" />
            
            {/* 8 Tentacles */}
            <g fill={variant === 'silhouette' ? '#c9d1d9' : 'url(#mascotGrad)'} stroke="#0d1117" strokeWidth="6">
              <path d="M 150 220 C 110 210, 60 180, 50 140 C 45 120, 65 110, 80 125 C 95 140, 115 175, 155 210 Z" />
              <path d="M 140 240 C 90 240, 40 220, 30 250 C 25 270, 50 280, 75 275 C 105 270, 130 255, 150 248 Z" />
              <path d="M 155 265 C 120 285, 75 320, 85 345 C 95 365, 120 350, 130 330 C 145 305, 160 285, 170 275 Z" />
              <path d="M 175 278 C 160 310, 150 350, 170 365 C 185 375, 195 355, 195 330 C 195 305, 190 285, 188 280 Z" />
              <path d="M 212 280 C 210 285, 205 305, 205 330 C 205 355, 215 375, 230 365 C 250 350, 240 310, 225 278 Z" />
              <path d="M 230 275 C 240 285, 255 305, 270 330 C 280 350, 305 365, 315 345 C 325 320, 280 285, 245 265 Z" />
              <path d="M 250 248 C 270 255, 295 270, 325 275 C 350 280, 375 270, 370 250 C 360 220, 310 240, 260 240 Z" />
              <path d="M 245 210 C 285 175, 305 140, 320 125 C 335 110, 355 120, 350 140 C 340 180, 290 210, 250 220 Z" />
              
              {/* Head Mantle */}
              <path d="M 130 210 C 120 150, 140 85, 200 85 C 260 85, 280 150, 270 210 C 265 245, 245 275, 200 275 C 155 275, 135 245, 130 210 Z" />
            </g>

            {/* Suction Cups / RJ45 dots */}
            <g fill="#7ee787">
              <circle cx="70" cy="135" r="8" />
              <circle cx="55" cy="260" r="8" />
              <circle cx="105" cy="335" r="8" />
              <circle cx="295" cy="335" r="8" />
              <circle cx="345" cy="260" r="8" />
              <circle cx="330" cy="135" r="8" />
            </g>

            {/* Eyes */}
            <ellipse cx="170" cy="175" rx="20" ry="26" fill="#ffffff" stroke="#0d1117" strokeWidth="4" />
            <ellipse cx="230" cy="175" rx="20" ry="26" fill="#ffffff" stroke="#0d1117" strokeWidth="4" />
            <ellipse cx="174" cy="177" rx="12" ry="16" fill="#0d1117" />
            <ellipse cx="226" cy="177" rx="12" ry="16" fill="#0d1117" />
            <circle cx="170" cy="170" r="5" fill="#58a6ff" />
            <circle cx="222" cy="170" r="5" fill="#58a6ff" />
            
            {/* Smile */}
            <path d="M 188 218 Q 200 230 212 218" fill="none" stroke="#0d1117" strokeWidth="6" strokeLinecap="round" />

            {/* Headband LED strip */}
            <rect x="150" y="105" width="100" height="20" rx="6" fill="#010409" stroke="#58a6ff" strokeWidth="3" />
            <circle cx="168" cy="115" r="4" fill="#7ee787" />
            <circle cx="188" cy="115" r="4" fill="#58a6ff" />
            <circle cx="212" cy="115" r="4" fill="#d29922" />
            <circle cx="232" cy="115" r="4" fill="#7ee787" />
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

import React from 'react';

export interface VashikaranChakraLogoProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | '3xl' | 'header' | 'full';
  variant?: 'emblem' | 'full';
  className?: string;
  showPulse?: boolean;
  backdrop?: boolean;
}

export const VashikaranChakraLogo: React.FC<VashikaranChakraLogoProps> = ({
  size = 'md',
  variant = 'emblem',
  className = '',
  showPulse = false,
  backdrop = false
}) => {
  const sizeMap: Record<string, string> = {
    xs: 'w-7 h-7',
    sm: 'w-10 h-10',
    md: 'w-14 h-14 sm:w-16 sm:h-16',
    header: 'w-14 h-14 sm:w-16 sm:h-16 lg:w-[72px] lg:h-[72px]',
    lg: 'w-20 h-20 sm:w-24 sm:h-24',
    xl: 'w-28 h-28 sm:w-36 sm:h-36',
    '2xl': 'w-36 h-36 sm:w-44 sm:h-44',
    '3xl': 'w-48 h-48 sm:w-56 sm:h-56',
    full: 'w-56 sm:w-64 md:w-72'
  };

  const dim = sizeMap[size];

  return (
    <div className={`relative flex items-center justify-center shrink-0 ${dim} ${backdrop ? 'p-2 rounded-full bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-blue-900/40 shadow-sm' : ''} ${className}`}>
      {/* Pure Vector Circular Logo Emblem - No Background, Only the Image */}
      <svg
        viewBox={variant === 'full' ? '0 0 1000 1120' : '0 0 1000 1000'}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full select-none transition-transform duration-300 hover:scale-105 drop-shadow-[0_2px_10px_rgba(16,39,84,0.18)] dark:drop-shadow-[0_2px_12px_rgba(43,82,146,0.3)]"
        aria-label="VASHIKARAN Cyber Chakra Emblem"
      >
        <g id="vashikaran-chakra-emblem">
          {/* 1. OUTER BROKEN RING (Thick Deep Navy / Cyber Cyan border with 4 quadrant gaps) */}
          <path
            d="M 77 500 A 425 425 0 0 1 494 75"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="26"
            strokeLinecap="square"
          />
          <path
            d="M 494 925 A 425 425 0 0 1 77 500"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="26"
            strokeLinecap="square"
          />
          <path
            d="M 506 75 A 425 425 0 0 1 506 925"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="26"
            strokeLinecap="square"
          />

          {/* Vertical Central Dividers (Top & Bottom Gaps) */}
          <line
            x1="500"
            y1="75"
            x2="500"
            y2="310"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="16"
            strokeLinecap="square"
          />
          <line
            x1="500"
            y1="690"
            x2="500"
            y2="925"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="16"
            strokeLinecap="square"
          />

          {/* 2. RIGHT HEMISPHERE: RADAR CONCENTRIC GRID */}
          <path
            d="M 500 260 A 240 240 0 0 1 740 500"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="10"
            strokeLinecap="square"
          />
          <path
            d="M 500 170 A 330 330 0 0 1 830 500"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="10"
            strokeLinecap="square"
          />
          <line
            x1="500"
            y1="500"
            x2="795"
            y2="205"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="8"
          />

          {/* Green Accent Arc passing through Right Network Mesh (R=330) */}
          <path
            d="M 720 270 A 330 330 0 0 1 740 680"
            stroke="#138808"
            className="dark:stroke-[#22C55E]"
            strokeWidth="12"
            strokeLinecap="round"
          />

          {/* 3. RIGHT HEMISPHERE: CYBER NETWORK MESH GRAPH */}
          <g
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="6"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            {/* Outer boundary edges */}
            <line x1="650" y1="180" x2="760" y2="240" />
            <line x1="760" y1="240" x2="840" y2="340" />
            <line x1="840" y1="340" x2="860" y2="470" />
            <line x1="860" y1="470" x2="820" y2="610" />
            <line x1="820" y1="610" x2="740" y2="740" />
            <line x1="740" y1="740" x2="620" y2="830" />
            <line x1="620" y1="830" x2="500" y2="840" />

            {/* Inner triangulation connections */}
            <line x1="650" y1="180" x2="620" y2="280" />
            <line x1="760" y1="240" x2="620" y2="280" />
            <line x1="760" y1="240" x2="720" y2="350" />
            <line x1="840" y1="340" x2="720" y2="350" />
            <line x1="840" y1="340" x2="760" y2="470" />
            <line x1="860" y1="470" x2="760" y2="470" />
            <line x1="860" y1="470" x2="730" y2="590" />
            <line x1="820" y1="610" x2="730" y2="590" />
            <line x1="820" y1="610" x2="670" y2="700" />
            <line x1="740" y1="740" x2="670" y2="700" />
            <line x1="740" y1="740" x2="570" y2="770" />
            <line x1="620" y1="830" x2="570" y2="770" />
            <line x1="500" y1="840" x2="570" y2="770" />

            {/* Internal cross chords */}
            <line x1="620" y1="280" x2="720" y2="350" />
            <line x1="720" y1="350" x2="760" y2="470" />
            <line x1="760" y1="470" x2="730" y2="590" />
            <line x1="730" y1="590" x2="670" y2="700" />
            <line x1="670" y1="700" x2="570" y2="770" />

            {/* Links to central axis and radar */}
            <line x1="500" y1="170" x2="650" y2="180" />
            <line x1="500" y1="260" x2="620" y2="280" />
            <line x1="500" y1="690" x2="570" y2="770" />
            <line x1="730" y1="590" x2="570" y2="770" />
            <line x1="500" y1="780" x2="620" y2="830" />
          </g>

          {/* Mesh Vertices / Data Nodes */}
          <g className="fill-[#102754] dark:fill-[#2B5292] transition-colors">
            <circle cx="650" cy="180" r="10" />
            <circle cx="760" cy="240" r="10" />
            <circle cx="840" cy="340" r="10" />
            <circle cx="860" cy="470" r="10" />
            <circle cx="820" cy="610" r="10" />
            <circle cx="740" cy="740" r="10" />
            <circle cx="620" cy="830" r="10" />
            <circle cx="500" cy="840" r="10" />
            <circle cx="620" cy="280" r="10" />
            <circle cx="720" cy="350" r="10" />
            <circle cx="760" cy="470" r="10" />
            <circle cx="730" cy="590" r="10" />
            <circle cx="670" cy="700" r="10" />
            <circle cx="570" cy="770" r="10" />
          </g>

          {/* Node Highlight Centers */}
          <g className="fill-white dark:fill-[#FFFFFF] transition-colors">
            <circle cx="650" cy="180" r="3.5" />
            <circle cx="760" cy="240" r="3.5" />
            <circle cx="840" cy="340" r="3.5" />
            <circle cx="860" cy="470" r="3.5" />
            <circle cx="820" cy="610" r="3.5" />
            <circle cx="740" cy="740" r="3.5" />
            <circle cx="620" cy="830" r="3.5" />
            <circle cx="500" cy="840" r="3.5" />
            <circle cx="620" cy="280" r="3.5" />
            <circle cx="720" cy="350" r="3.5" />
            <circle cx="760" cy="470" r="3.5" />
            <circle cx="730" cy="590" r="3.5" />
            <circle cx="670" cy="700" r="3.5" />
            <circle cx="570" cy="770" r="3.5" />
          </g>

          {/* 4. LEFT HEMISPHERE: TRICOLOR SAFFRON & GREEN ACCENTS */}
          {/* Saffron / Orange Accent Arc (R=240, upper-left quadrant) */}
          <path
            d="M 270 415 A 240 240 0 0 1 485 262"
            stroke="#FF9933"
            strokeWidth="14"
            strokeLinecap="round"
          />

          {/* India Green Accent Arc (R=240, lower-left quadrant) */}
          <path
            d="M 485 738 A 240 240 0 0 1 270 585"
            stroke="#138808"
            strokeWidth="14"
            strokeLinecap="round"
          />

          {/* 5. LEFT HEMISPHERE: CYBER CIRCUITRY TRACES & NODES */}
          {/* Inner concentric circuit track (R=305) */}
          <path
            d="M 198 500 A 305 305 0 0 1 370 248"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="8"
            strokeLinecap="round"
          />
          <line
            x1="370"
            y1="248"
            x2="340"
            y2="305"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="8"
            strokeLinecap="round"
          />
          <circle cx="340" cy="305" r="12" className="fill-[#102754] dark:fill-[#2B5292] transition-colors" />
          <circle cx="340" cy="305" r="4.5" className="fill-white dark:fill-[#FFFFFF] transition-colors" />

          {/* Outer concentric circuit track (R=365) */}
          <path
            d="M 136 500 A 365 365 0 0 1 280 260"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="8"
            strokeLinecap="round"
          />
          <circle cx="280" cy="260" r="12" className="fill-[#102754] dark:fill-[#2B5292] transition-colors" />
          <circle cx="280" cy="260" r="4.5" className="fill-white dark:fill-[#FFFFFF] transition-colors" />

          {/* Lower-Left Inner Circuit track (R=305) */}
          <path
            d="M 198 500 A 305 305 0 0 0 348 732"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="8"
            strokeLinecap="round"
          />
          <circle cx="348" cy="732" r="12" className="fill-[#102754] dark:fill-[#2B5292] transition-colors" />
          <circle cx="348" cy="732" r="4.5" className="fill-white dark:fill-[#FFFFFF] transition-colors" />

          {/* Lower-Left Outer Circuit track (R=365) */}
          <path
            d="M 136 500 A 365 365 0 0 0 280 740"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="8"
            strokeLinecap="round"
          />
          <circle cx="280" cy="740" r="12" className="fill-[#102754] dark:fill-[#2B5292] transition-colors" />
          <circle cx="280" cy="740" r="4.5" className="fill-white dark:fill-[#FFFFFF] transition-colors" />

          {/* Horizontal connector through left gap to external terminal node */}
          <line
            x1="140"
            y1="500"
            x2="80"
            y2="500"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="10"
            strokeLinecap="round"
          />
          <circle cx="80" cy="500" r="14" className="fill-[#102754] dark:fill-[#2B5292] transition-colors" />
          <circle cx="80" cy="500" r="5" className="fill-white dark:fill-[#FFFFFF] transition-colors" />

          {/* CYBER SECURITY SHIELD EMBLEM AT 9 O'CLOCK */}
          <g transform="translate(145, 500)">
            <path
              d="M -24 -36 L 24 -36 C 24 -10 24 18 0 42 C -24 18 -24 -10 -24 -36 Z"
              className="fill-[#102754] stroke-[#102754] dark:fill-[#2B5292] dark:stroke-[#2B5292] transition-colors"
              strokeWidth="4"
              strokeLinejoin="round"
            />
            {/* Shield Left Half Accent */}
            <path
              d="M -20 -32 L 0 -32 L 0 36 C -18 16 -18 -8 -20 -32 Z"
              className="fill-cyan-600 dark:fill-[#3864AC] transition-colors"
            />
            {/* Shield Right Half Dark Accent */}
            <path
              d="M 0 -32 L 20 -32 C 18 -8 18 16 0 36 Z"
              className="fill-[#0F172A] dark:fill-[#102754] transition-colors"
            />
            {/* Shield Center Divider */}
            <line x1="0" y1="-32" x2="0" y2="36" stroke="#FFFFFF" strokeWidth="2" />
          </g>

          {/* 6. ASHOKA CHAKRA (CENTERPIECE) */}
          {/* Chakra Outer Rim */}
          <circle
            cx="500"
            cy="500"
            r="186"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="12"
            fill="none"
          />

          {/* Chakra Inner Hub Border */}
          <circle
            cx="500"
            cy="500"
            r="64"
            className="stroke-[#102754] dark:stroke-[#2B5292] transition-colors"
            strokeWidth="6"
            fill="none"
          />

          {/* Solid Inner Center Hub */}
          <circle
            cx="500"
            cy="500"
            r="46"
            className="fill-[#102754] dark:fill-[#2B5292] transition-colors"
          />

          {/* 24 Authentic Ashoka Chakra Spokes (Each rotated by 15°) */}
          <g className="fill-[#102754] dark:fill-[#2B5292] transition-colors">
            <polygon points="500,436 496,436 498,318 502,318 504,436" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(15 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(30 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(45 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(60 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(75 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(90 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(105 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(120 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(135 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(150 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(165 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(180 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(195 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(210 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(225 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(240 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(255 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(270 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(285 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(300 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(315 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(330 500 500)" />
            <polygon points="500,436 496,436 498,318 502,318 504,436" transform="rotate(345 500 500)" />
          </g>

          {/* 24 Small Beads between spokes near the rim */}
          <g className="fill-[#102754] dark:fill-[#2B5292] transition-colors">
            <circle cx="500" cy="322" r="3" transform="rotate(7.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(22.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(37.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(52.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(67.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(82.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(97.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(112.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(127.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(142.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(157.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(172.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(187.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(202.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(217.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(232.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(247.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(262.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(277.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(292.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(307.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(322.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(337.5 500 500)" />
            <circle cx="500" cy="322" r="3" transform="rotate(352.5 500 500)" />
          </g>
        </g>

        {/* 7. TYPOGRAPHY: VASHIKARAN (Rendered when variant is 'full' matching user lockup) */}
        {variant === 'full' && (
          <text
            x="500"
            y="1055"
            textAnchor="middle"
            className="fill-[#102754] dark:fill-[#2B5292] font-sans select-none"
            style={{
              fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
              fontWeight: 900,
              fontSize: '82px',
              letterSpacing: '0.18em'
            }}
          >
            VASHIKARAN
          </text>
        )}
      </svg>

      {/* Active telemetry heartbeat indicator */}
      {showPulse && (
        <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500 border border-white dark:border-slate-900 shadow-[0_0_6px_#06b6d4]" />
        </span>
      )}
    </div>
  );
};


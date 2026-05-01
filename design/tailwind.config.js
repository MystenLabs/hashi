/* Mirrors the Sui docs Tailwind setup, with our hashi color palette
   wired into the same `sui-*` shorthand that the ported components use. */
const defaultTheme = require("tailwindcss/defaultTheme");

module.exports = {
  corePlugins: {
    preflight: false, // disable Tailwind's reset (Docusaurus has its own)
  },
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./docs/**/*.{md,mdx}",
    "./content/**/*.{md,mdx}",
  ],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      fontFamily: {
        sans: ["ABCNormal", ...defaultTheme.fontFamily.sans],
      },
      colors: {
        "sui-black": "var(--hashi-black)",
        "sui-blue": "var(--hashi-blue)",
        "sui-blue-primary": "var(--hashi-blue)",
        "sui-blue-bright": "var(--hashi-blue-bright)",
        "sui-blue-light": "var(--hashi-blue-light)",
        "sui-blue-lighter": "var(--hashi-blue-lighter)",
        "sui-blue-dark": "var(--hashi-blue-dark)",
        "sui-blue-darker": "var(--hashi-blue-darker)",
        "sui-hero": "var(--hashi-blue-dark)",
        "sui-hero-dark": "var(--hashi-blue-darker)",
        "sui-success": "var(--hashi-blue)",
        "sui-success-dark": "var(--hashi-blue-dark)",
        "sui-success-light": "var(--hashi-blue-light)",
        "sui-issue": "var(--hashi-blue)",
        "sui-issue-dark": "var(--hashi-blue-dark)",
        "sui-issue-light": "var(--hashi-blue-light)",
        "sui-warning": "var(--hashi-blue)",
        "sui-warning-dark": "var(--hashi-blue-dark)",
        "sui-warning-light": "var(--hashi-blue-light)",
        "sui-code": "var(--hashi-blue)",
        "sui-gray": {
          35: "#F4F5F7",
          40: "#E0E2E6",
          45: "#C2C6CD",
          50: "#C2C6CD",
          55: "#C2C6CD",
          60: "#A1A7B2",
          65: "#89919F",
          70: "#89919F",
          75: "#6C7584",
          80: "#6C7584",
          85: "#4B515B",
          90: "#343940",
          95: "#222529",
          100: "#131518",
        },
        "sui-ghost-white": "#ffffff",
        "sui-ghost-dark": "#131518",
        "sui-line": "rgba(255,255,255,0.1)",
      },
      backgroundImage: {
        checkerboard:
          "linear-gradient(45deg, var(--hashi-blue) 25%, transparent 25%, transparent 75%, var(--hashi-blue) 75%, var(--hashi-blue)), linear-gradient(45deg, var(--hashi-blue) 25%, transparent 25%, transparent 75%, var(--hashi-blue) 75%, var(--hashi-blue))",
        "checkerboard-dark":
          "linear-gradient(45deg, var(--hashi-blue-darker) 25%, transparent 25%, transparent 75%, var(--hashi-blue-darker) 75%, var(--hashi-blue-darker)), linear-gradient(45deg, var(--hashi-blue-darker) 25%, transparent 25%, transparent 75%, var(--hashi-blue-darker) 75%, var(--hashi-blue-darker))",
      },
      backgroundSize: {
        checkerboard: "20px 20px",
      },
    },
  },
  plugins: [],
};

import type { SuiCodegenConfig } from "@mysten/codegen";

const config: SuiCodegenConfig = {
  output: "./src",
  packages: [
    {
      package: "@local-pkg/hashi",
      path: "../../../packages/hashi",
    },
  ],
};

export default config;

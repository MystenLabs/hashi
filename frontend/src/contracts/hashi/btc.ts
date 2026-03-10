/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/** Module: btc */

import { MoveStruct } from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
const $moduleName = "@local-pkg/hashi::btc";
export const BTC = new MoveStruct({
  name: `${$moduleName}::BTC`,
  fields: {
    id: bcs.Address,
  },
});

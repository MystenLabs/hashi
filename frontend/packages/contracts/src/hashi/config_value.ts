/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveEnum } from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
const $moduleName = "@local-pkg/hashi::config_value";
export const Value = new MoveEnum({
  name: `${$moduleName}::Value`,
  fields: {
    U64: bcs.u64(),
    Address: bcs.Address,
    String: bcs.string(),
    Bool: bcs.bool(),
    Bytes: bcs.vector(bcs.u8()),
  },
});

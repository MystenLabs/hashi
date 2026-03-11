/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import * as object_bag from "./deps/sui/object_bag.js";
const $moduleName = "@local-pkg/hashi::treasury";
export const Treasury = new MoveStruct({
  name: `${$moduleName}::Treasury`,
  fields: {
    objects: object_bag.ObjectBag,
  },
});
export const Key = new MoveStruct({
  name: `${$moduleName}::Key<phantom T>`,
  fields: {
    dummy_field: bcs.bool(),
  },
});
export const MintEvent = new MoveStruct({
  name: `${$moduleName}::MintEvent<phantom T>`,
  fields: {
    amount: bcs.u64(),
  },
});
export const BurnEvent = new MoveStruct({
  name: `${$moduleName}::BurnEvent<phantom T>`,
  fields: {
    amount: bcs.u64(),
  },
});

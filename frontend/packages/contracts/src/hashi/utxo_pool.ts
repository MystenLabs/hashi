/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import * as bag from "./deps/sui/bag.js";
import * as utxo from "./utxo.js";
const $moduleName = "@local-pkg/hashi::utxo_pool";
export const UtxoPool = new MoveStruct({
  name: `${$moduleName}::UtxoPool`,
  fields: {
    active_utxos: bag.Bag,
    spent_utxos: bag.Bag,
  },
});
export const UtxoSpentEvent = new MoveStruct({
  name: `${$moduleName}::UtxoSpentEvent`,
  fields: {
    utxo_id: utxo.UtxoId,
    spent_epoch: bcs.u64(),
  },
});
export const SpentUtxoDeletedEvent = new MoveStruct({
  name: `${$moduleName}::SpentUtxoDeletedEvent`,
  fields: {
    utxo_id: utxo.UtxoId,
  },
});

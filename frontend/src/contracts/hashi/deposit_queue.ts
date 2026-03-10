/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import {
  MoveStruct,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import { type Transaction } from "@mysten/sui/transactions";
import * as bag from "./deps/sui/bag.js";
import * as utxo from "./utxo.js";
const $moduleName = "@local-pkg/hashi::deposit_queue";
export const DepositRequestQueue = new MoveStruct({
  name: `${$moduleName}::DepositRequestQueue`,
  fields: {
    requests: bag.Bag,
  },
});
export const DepositRequest = new MoveStruct({
  name: `${$moduleName}::DepositRequest`,
  fields: {
    id: bcs.Address,
    utxo: utxo.Utxo,
    timestamp_ms: bcs.u64(),
  },
});
export interface DepositRequestArguments {
  utxo: RawTransactionArgument<string>;
}
export interface DepositRequestOptions {
  package?: string;
  arguments: DepositRequestArguments | [utxo: RawTransactionArgument<string>];
}
export function depositRequest(options: DepositRequestOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "0x2::clock::Clock"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["utxo"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "deposit_queue",
      function: "deposit_request",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}

/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/** Module: hashi */

import {
  MoveStruct,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import { type Transaction } from "@mysten/sui/transactions";
import * as committee_set from "./committee_set.js";
import * as config from "./config.js";
import * as treasury from "./treasury.js";
import * as deposit_queue from "./deposit_queue.js";
import * as withdrawal_queue from "./withdrawal_queue.js";
import * as utxo_pool from "./utxo_pool.js";
import * as bag from "./deps/sui/bag.js";
const $moduleName = "@local-pkg/hashi::hashi";
export const Hashi = new MoveStruct({
  name: `${$moduleName}::Hashi`,
  fields: {
    id: bcs.Address,
    committee_set: committee_set.CommitteeSet,
    config: config.Config,
    treasury: treasury.Treasury,
    deposit_queue: deposit_queue.DepositRequestQueue,
    withdrawal_queue: withdrawal_queue.WithdrawalRequestQueue,
    utxo_pool: utxo_pool.UtxoPool,
    proposals: bag.Bag,
    /** TOB certificates by (epoch, batch_index) -> EpochCertsV1 */
    tob: bag.Bag,
  },
});
export interface RegisterBtcArguments {
  self: RawTransactionArgument<string>;
  coinRegistry: RawTransactionArgument<string>;
}
export interface RegisterBtcOptions {
  package?: string;
  arguments:
    | RegisterBtcArguments
    | [
        self: RawTransactionArgument<string>,
        coinRegistry: RawTransactionArgument<string>,
      ];
}
export function registerBtc(options: RegisterBtcOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, null] satisfies (string | null)[];
  const parameterNames = ["self", "coinRegistry"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "hashi",
      function: "register_btc",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface RegisterUpgradeCapArguments {
  self: RawTransactionArgument<string>;
  upgradeCap: RawTransactionArgument<string>;
}
export interface RegisterUpgradeCapOptions {
  package?: string;
  arguments:
    | RegisterUpgradeCapArguments
    | [
        self: RawTransactionArgument<string>,
        upgradeCap: RawTransactionArgument<string>,
      ];
}
export function registerUpgradeCap(options: RegisterUpgradeCapOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, null] satisfies (string | null)[];
  const parameterNames = ["self", "upgradeCap"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "hashi",
      function: "register_upgrade_cap",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}

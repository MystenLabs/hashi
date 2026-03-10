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
import * as utxo from "./utxo.js";
const $moduleName = "@local-pkg/hashi::deposit";
export const DepositRequestedEvent = new MoveStruct({
  name: `${$moduleName}::DepositRequestedEvent`,
  fields: {
    request_id: bcs.Address,
    utxo_id: utxo.UtxoId,
    amount: bcs.u64(),
    derivation_path: bcs.option(bcs.Address),
    timestamp_ms: bcs.u64(),
  },
});
export const DepositConfirmedEvent = new MoveStruct({
  name: `${$moduleName}::DepositConfirmedEvent`,
  fields: {
    request_id: bcs.Address,
    utxo_id: utxo.UtxoId,
    amount: bcs.u64(),
    derivation_path: bcs.option(bcs.Address),
  },
});
export const ExpiredDepositDeletedEvent = new MoveStruct({
  name: `${$moduleName}::ExpiredDepositDeletedEvent`,
  fields: {
    request_id: bcs.Address,
  },
});
export interface DepositArguments {
  hashi: RawTransactionArgument<string>;
  request: RawTransactionArgument<string>;
  fee: RawTransactionArgument<string>;
}
export interface DepositOptions {
  package?: string;
  arguments:
    | DepositArguments
    | [
        hashi: RawTransactionArgument<string>,
        request: RawTransactionArgument<string>,
        fee: RawTransactionArgument<string>,
      ];
}
export function deposit(options: DepositOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, null, null] satisfies (string | null)[];
  const parameterNames = ["hashi", "request", "fee"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "deposit",
      function: "deposit",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface ConfirmDepositArguments {
  hashi: RawTransactionArgument<string>;
  requestId: RawTransactionArgument<string>;
  signature: RawTransactionArgument<string>;
}
export interface ConfirmDepositOptions {
  package?: string;
  arguments:
    | ConfirmDepositArguments
    | [
        hashi: RawTransactionArgument<string>,
        requestId: RawTransactionArgument<string>,
        signature: RawTransactionArgument<string>,
      ];
}
export function confirmDeposit(options: ConfirmDepositOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", null] satisfies (string | null)[];
  const parameterNames = ["hashi", "requestId", "signature"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "deposit",
      function: "confirm_deposit",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface DeleteExpiredDepositArguments {
  hashi: RawTransactionArgument<string>;
  requestId: RawTransactionArgument<string>;
}
export interface DeleteExpiredDepositOptions {
  package?: string;
  arguments:
    | DeleteExpiredDepositArguments
    | [
        hashi: RawTransactionArgument<string>,
        requestId: RawTransactionArgument<string>,
      ];
}
export function deleteExpiredDeposit(options: DeleteExpiredDepositOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "address", "0x2::clock::Clock"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["hashi", "requestId"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "deposit",
      function: "delete_expired_deposit",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}

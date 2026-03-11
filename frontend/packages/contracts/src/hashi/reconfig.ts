/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/** Module: reconfig */

import {
  MoveStruct,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import { type Transaction } from "@mysten/sui/transactions";
const $moduleName = "@local-pkg/hashi::reconfig";
export const ReconfigCompletionMessage = new MoveStruct({
  name: `${$moduleName}::ReconfigCompletionMessage`,
  fields: {
    /** The epoch of the new committee. */
    epoch: bcs.u64(),
    /** The MPC committee's threshold public key. */
    mpc_public_key: bcs.vector(bcs.u8()),
  },
});
export const StartReconfigEvent = new MoveStruct({
  name: `${$moduleName}::StartReconfigEvent`,
  fields: {
    epoch: bcs.u64(),
  },
});
export const EndReconfigEvent = new MoveStruct({
  name: `${$moduleName}::EndReconfigEvent`,
  fields: {
    epoch: bcs.u64(),
    /** The MPC committee's threshold public key. */
    mpc_public_key: bcs.vector(bcs.u8()),
  },
});
export const AbortReconfigEvent = new MoveStruct({
  name: `${$moduleName}::AbortReconfigEvent`,
  fields: {
    epoch: bcs.u64(),
  },
});
export interface StartReconfigArguments {
  self: RawTransactionArgument<string>;
}
export interface StartReconfigOptions {
  package?: string;
  arguments: StartReconfigArguments | [self: RawTransactionArgument<string>];
}
export function startReconfig(options: StartReconfigOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "0x3::sui_system::SuiSystemState"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["self"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "reconfig",
      function: "start_reconfig",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface EndReconfigArguments {
  self: RawTransactionArgument<string>;
  mpcPublicKey: RawTransactionArgument<number[]>;
  signature: RawTransactionArgument<number[]>;
  signersBitmap: RawTransactionArgument<number[]>;
}
export interface EndReconfigOptions {
  package?: string;
  arguments:
    | EndReconfigArguments
    | [
        self: RawTransactionArgument<string>,
        mpcPublicKey: RawTransactionArgument<number[]>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
      ];
}
export function endReconfig(options: EndReconfigOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "vector<u8>",
    "vector<u8>",
    "vector<u8>",
  ] satisfies (string | null)[];
  const parameterNames = ["self", "mpcPublicKey", "signature", "signersBitmap"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "reconfig",
      function: "end_reconfig",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface AbortReconfigArguments {
  Self: RawTransactionArgument<string>;
}
export interface AbortReconfigOptions {
  package?: string;
  arguments: AbortReconfigArguments | [Self: RawTransactionArgument<string>];
}
export function abortReconfig(options: AbortReconfigOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null] satisfies (string | null)[];
  const parameterNames = ["Self"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "reconfig",
      function: "abort_reconfig",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}

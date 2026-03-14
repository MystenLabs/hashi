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
import * as config_value from "./config_value.js";
const $moduleName = "@local-pkg/hashi::update_config";
export const UpdateConfig = new MoveStruct({
  name: `${$moduleName}::UpdateConfig`,
  fields: {
    key: bcs.string(),
    value: config_value.Value,
  },
});
export interface ProposeArguments {
  hashi: RawTransactionArgument<string>;
  key: RawTransactionArgument<string>;
  value: RawTransactionArgument<string>;
  metadata: RawTransactionArgument<string>;
}
export interface ProposeOptions {
  package?: string;
  arguments:
    | ProposeArguments
    | [
        hashi: RawTransactionArgument<string>,
        key: RawTransactionArgument<string>,
        value: RawTransactionArgument<string>,
        metadata: RawTransactionArgument<string>,
      ];
}
export function propose(options: ProposeOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "0x1::string::String",
    null,
    null,
    "0x2::clock::Clock",
  ] satisfies (string | null)[];
  const parameterNames = ["hashi", "key", "value", "metadata"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "update_config",
      function: "propose",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface ExecuteArguments {
  hashi: RawTransactionArgument<string>;
  proposalId: RawTransactionArgument<string>;
}
export interface ExecuteOptions {
  package?: string;
  arguments:
    | ExecuteArguments
    | [
        hashi: RawTransactionArgument<string>,
        proposalId: RawTransactionArgument<string>,
      ];
}
export function execute(options: ExecuteOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [
    null,
    "0x2::object::ID",
    "0x2::clock::Clock",
  ] satisfies (string | null)[];
  const parameterNames = ["hashi", "proposalId"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "update_config",
      function: "execute",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}

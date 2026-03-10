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
const $moduleName = "@local-pkg/hashi::enable_version";
export const EnableVersion = new MoveStruct({
  name: `${$moduleName}::EnableVersion`,
  fields: {
    version: bcs.u64(),
  },
});
export interface ProposeArguments {
  hashi: RawTransactionArgument<string>;
  version: RawTransactionArgument<number | bigint>;
  metadata: RawTransactionArgument<string>;
}
export interface ProposeOptions {
  package?: string;
  arguments:
    | ProposeArguments
    | [
        hashi: RawTransactionArgument<string>,
        version: RawTransactionArgument<number | bigint>,
        metadata: RawTransactionArgument<string>,
      ];
}
export function propose(options: ProposeOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "u64", null, "0x2::clock::Clock"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["hashi", "version", "metadata"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "enable_version",
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
      module: "enable_version",
      function: "execute",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}

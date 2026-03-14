/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import {
  MoveEnum,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { bcs } from "@mysten/sui/bcs";
import { type Transaction } from "@mysten/sui/transactions";
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
export interface NewU64Arguments {
  value: RawTransactionArgument<number | bigint>;
}
export interface NewU64Options {
  package?: string;
  arguments: NewU64Arguments | [value: RawTransactionArgument<number | bigint>];
}
export function newU64(options: NewU64Options) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = ["u64"] satisfies (string | null)[];
  const parameterNames = ["value"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "config_value",
      function: "new_u64",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface NewAddressArguments {
  value: RawTransactionArgument<string>;
}
export interface NewAddressOptions {
  package?: string;
  arguments: NewAddressArguments | [value: RawTransactionArgument<string>];
}
export function newAddress(options: NewAddressOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = ["address"] satisfies (string | null)[];
  const parameterNames = ["value"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "config_value",
      function: "new_address",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface NewStringArguments {
  value: RawTransactionArgument<string>;
}
export interface NewStringOptions {
  package?: string;
  arguments: NewStringArguments | [value: RawTransactionArgument<string>];
}
export function newString(options: NewStringOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = ["0x1::string::String"] satisfies (string | null)[];
  const parameterNames = ["value"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "config_value",
      function: "new_string",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface NewBoolArguments {
  value: RawTransactionArgument<boolean>;
}
export interface NewBoolOptions {
  package?: string;
  arguments: NewBoolArguments | [value: RawTransactionArgument<boolean>];
}
export function newBool(options: NewBoolOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = ["bool"] satisfies (string | null)[];
  const parameterNames = ["value"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "config_value",
      function: "new_bool",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}
export interface NewBytesArguments {
  value: RawTransactionArgument<number[]>;
}
export interface NewBytesOptions {
  package?: string;
  arguments: NewBytesArguments | [value: RawTransactionArgument<number[]>];
}
export function newBytes(options: NewBytesOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = ["vector<u8>"] satisfies (string | null)[];
  const parameterNames = ["value"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "config_value",
      function: "new_bytes",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
    });
}

/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { type BcsType, bcs } from "@mysten/sui/bcs";
import {
  MoveStruct,
  normalizeMoveArguments,
  type RawTransactionArgument,
} from "../utils/index.js";
import { type Transaction } from "@mysten/sui/transactions";
import * as vec_map from "./deps/sui/vec_map.js";
const $moduleName = "@local-pkg/hashi::proposal";
export function Proposal<T extends BcsType<any>>(...typeParameters: [T]) {
  return new MoveStruct({
    name: `${$moduleName}::Proposal<${typeParameters[0].name as T["name"]}>`,
    fields: {
      id: bcs.Address,
      creator: bcs.Address,
      votes: bcs.vector(bcs.Address),
      quorum_threshold_bps: bcs.u64(),
      timestamp_ms: bcs.u64(),
      metadata: vec_map.VecMap(bcs.string(), bcs.string()),
      data: typeParameters[0],
    },
  });
}
export interface VoteArguments {
  hashi: RawTransactionArgument<string>;
  proposalId: RawTransactionArgument<string>;
}
export interface VoteOptions {
  package?: string;
  arguments:
    | VoteArguments
    | [
        hashi: RawTransactionArgument<string>,
        proposalId: RawTransactionArgument<string>,
      ];
  typeArguments: [string];
}
export function vote(options: VoteOptions) {
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
      module: "proposal",
      function: "vote",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
      typeArguments: options.typeArguments,
    });
}
export interface RemoveVoteArguments {
  hashi: RawTransactionArgument<string>;
  proposalId: RawTransactionArgument<string>;
}
export interface RemoveVoteOptions {
  package?: string;
  arguments:
    | RemoveVoteArguments
    | [
        hashi: RawTransactionArgument<string>,
        proposalId: RawTransactionArgument<string>,
      ];
  typeArguments: [string];
}
export function removeVote(options: RemoveVoteOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "0x2::object::ID"] satisfies (string | null)[];
  const parameterNames = ["hashi", "proposalId"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "proposal",
      function: "remove_vote",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
      typeArguments: options.typeArguments,
    });
}
export interface QuorumReachedArguments {
  proposal: RawTransactionArgument<string>;
  hashi: RawTransactionArgument<string>;
}
export interface QuorumReachedOptions {
  package?: string;
  arguments:
    | QuorumReachedArguments
    | [
        proposal: RawTransactionArgument<string>,
        hashi: RawTransactionArgument<string>,
      ];
  typeArguments: [string];
}
export function quorumReached(options: QuorumReachedOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, null] satisfies (string | null)[];
  const parameterNames = ["proposal", "hashi"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "proposal",
      function: "quorum_reached",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
      typeArguments: options.typeArguments,
    });
}
export interface IsExpiredArguments {
  proposal: RawTransactionArgument<string>;
}
export interface IsExpiredOptions {
  package?: string;
  arguments: IsExpiredArguments | [proposal: RawTransactionArgument<string>];
  typeArguments: [string];
}
export function isExpired(options: IsExpiredOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null, "0x2::clock::Clock"] satisfies (
    | string
    | null
  )[];
  const parameterNames = ["proposal"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "proposal",
      function: "is_expired",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
      typeArguments: options.typeArguments,
    });
}
export interface DeleteExpiredArguments {
  hashi: RawTransactionArgument<string>;
  proposalId: RawTransactionArgument<string>;
}
export interface DeleteExpiredOptions {
  package?: string;
  arguments:
    | DeleteExpiredArguments
    | [
        hashi: RawTransactionArgument<string>,
        proposalId: RawTransactionArgument<string>,
      ];
  typeArguments: [string];
}
export function deleteExpired(options: DeleteExpiredOptions) {
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
      module: "proposal",
      function: "delete_expired",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
      typeArguments: options.typeArguments,
    });
}
export interface VotesArguments {
  proposal: RawTransactionArgument<string>;
}
export interface VotesOptions {
  package?: string;
  arguments: VotesArguments | [proposal: RawTransactionArgument<string>];
  typeArguments: [string];
}
export function votes(options: VotesOptions) {
  const packageAddress = options.package ?? "@local-pkg/hashi";
  const argumentsTypes = [null] satisfies (string | null)[];
  const parameterNames = ["proposal"];
  return (tx: Transaction) =>
    tx.moveCall({
      package: packageAddress,
      module: "proposal",
      function: "votes",
      arguments: normalizeMoveArguments(
        options.arguments,
        argumentsTypes,
        parameterNames,
      ),
      typeArguments: options.typeArguments,
    });
}

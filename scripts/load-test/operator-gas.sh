#!/usr/bin/env bash
# Read-only: every registered member's operator address and its SUI balance, as
# "operator<TAB>endpoint<TAB>sui" sorted lowest first. Leaders pay the gas for every
# approval, confirmation and withdrawal step, so a series drains each operator;
# compare a snapshot from before with one from after.
# Usage: GRAPHQL_URL=https://graphql.testnet.sui.io/graphql operator-gas.sh
# shellcheck disable=SC2016
set -euo pipefail
: "${GRAPHQL_URL:?}" "${HASHI_OBJECT_ID:?}"

gql() {
  local reply
  reply=$(jq -n --arg query "$1" --argjson variables "${2:-null}" '{query: $query, variables: $variables}' \
    | curl -sS -m 40 -H 'Content-Type: application/json' -d @- "$GRAPHQL_URL")
  if jq -e '(.errors // []) | length > 0' <<< "$reply" > /dev/null; then
    echo "operator-gas: $(jq -c .errors <<< "$reply" | cut -c1-400)" >&2
    return 1
  fi
  printf '%s' "$reply"
}

members=$(gql 'query($id: SuiAddress!) { object(address: $id) { asMoveObject { contents { json } } } }' \
  "{\"id\":\"$HASHI_OBJECT_ID\"}" | jq -er '.data.object.asMoveObject.contents.json.committee_set.members')
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

cursor=null
while :; do
  page=$(gql 'query($id: SuiAddress!, $after: String) { address(address: $id) { dynamicFields(first: 50, after: $after) {
      pageInfo { hasNextPage endCursor } nodes { value { ... on MoveValue { json } } } } } }' \
    "{\"id\":$(jq '.id' <<< "$members"),\"after\":$cursor}")
  jq -r '.data.address.dynamicFields.nodes[].value.json | [.operator_address, .endpoint_url] | @tsv' <<< "$page" >> "$tmp/members"
  [ "$(jq -r '.data.address.dynamicFields.pageInfo.hasNextPage' <<< "$page")" = true ] || break
  cursor=$(jq '.data.address.dynamicFields.pageInfo.endCursor' <<< "$page")
done
# Dynamic-field pagination can drop entries, so check against the table's own size.
if [ "$(wc -l < "$tmp/members" | tr -d ' ')" != "$(jq -r .size <<< "$members")" ]; then
  echo "operator-gas: read $(wc -l < "$tmp/members" | tr -d ' ') members, the table holds $(jq -r .size <<< "$members")" >&2
  exit 1
fi

cut -f1 "$tmp/members" | split -l 20 - "$tmp/chunk-"
for chunk in "$tmp"/chunk-*; do
  query="query {"
  i=0
  while read -r operator; do
    query+=" a$i: address(address: \"$operator\") { address balance(coinType: \"0x2::sui::SUI\") { totalBalance } }"
    i=$((i + 1))
  done < "$chunk"
  gql "$query }" | jq -r '.data[] | [.address, (.balance.totalBalance | tonumber / 1e9)] | @tsv' >> "$tmp/balances"
done
join -t $'\t' <(sort "$tmp/members") <(sort "$tmp/balances") | sort -t $'\t' -k3 -n

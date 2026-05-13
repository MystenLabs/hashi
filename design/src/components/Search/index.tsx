// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Full-page search results component (rendered at /search). Mirrors the
// Sui docs Search component, configured for the single Hashi Docs index
// on the shared MystenLabs Algolia application.

import React from "react";
import { liteClient as algoliasearch } from "algoliasearch/lite";
import { InstantSearch, Index } from "react-instantsearch";

import ControlledSearchBox from "./ControlledSearchBox";
import TabbedResults from "./TabbedResults";
import IndexStatsCollector from "./IndexStatsCollector";
import TabbedIndex from "./TabbedIndex";

function getQueryParam(key) {
  const params = new URLSearchParams(
    typeof window !== "undefined" ? window.location.search : "",
  );
  return params.get(key) || "";
}

export default function Search() {
  const searchClient = algoliasearch(
    // Shared MystenLabs Algolia app. Hashi-only search-only key.
    "M9JD2UP87M",
    "02b69f5ef993a11c422df2c9ecedfa4d",
  );

  const queryParam = getQueryParam("q");

  // Multi-index search across the MystenLabs docs hosted on the shared
  // Algolia app. Available indices not currently surfaced: suins_docs,
  // walrus_docs, seal_docs — add entries here to extend.
  const tabs = [
    { label: "Hashi", indexName: "Hashi Docs" },
    { label: "Sui", indexName: "sui_docs" },
    { label: "The Move Book", indexName: "move_book" },
    { label: "SDKs", indexName: "sui_sdks" },
  ];

  const [activeTab, setActiveTab] = React.useState(tabs[0].indexName);
  const [tabCounts, setTabCounts] = React.useState<Record<string, number>>({
    "Hashi Docs": 0,
    sui_docs: 0,
    move_book: 0,
    sui_sdks: 0,
  });
  const [query, setQuery] = React.useState(queryParam);

  const handleVisibility = React.useCallback(
    (indexName: string, nbHits: number) => {
      setTabCounts((prev) => ({ ...prev, [indexName]: nbHits }));
    },
    [],
  );

  return (
    <InstantSearch
      searchClient={searchClient}
      indexName={tabs[0].indexName}
      future={{ preserveSharedStateOnUnmount: true }}
      initialUiState={Object.fromEntries(
        tabs.map((tab) => [tab.indexName, { query: queryParam }]),
      )}
    >
      {/* Preload tab visibility */}
      {tabs.map((tab) => (
        <Index indexName={tab.indexName} key={`stat-${tab.indexName}`}>
          <IndexStatsCollector
            indexName={tab.indexName}
            onUpdate={handleVisibility}
          />
        </Index>
      ))}

      <div className="grid grid-cols-12 gap-4 hashi-search">
        <div className="col-span-12">
          <ControlledSearchBox
            placeholder={`Search`}
            query={query}
            onChange={setQuery}
          />
        </div>
        <div className="col-span-12">
          <TabbedResults
            activeTab={activeTab}
            onChange={setActiveTab}
            tabs={tabs.map((tab) => ({
              ...tab,
              count: tabCounts[tab.indexName] || 0,
            }))}
          />
        </div>
        <div className="col-span-12">
          {tabs.map((tab) => (
            <div
              key={tab.indexName}
              className={`flex ${activeTab === tab.indexName ? "block" : "hidden"}`}
            >
              <TabbedIndex indexName={tab.indexName} query={query} />
            </div>
          ))}
        </div>
      </div>
    </InstantSearch>
  );
}

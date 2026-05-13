// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";

export default function TabbedResults({
  activeTab,
  onChange,
  tabs,
  showTooltips = true,
}) {
  const tooltipFor = (label: string) => {
    if (label === "Hashi") return "Search results from the Hashi design docs";
    if (label === "Sui") return "Search results from the official Sui Docs";
    if (label === "SuiNS") return "Search results from Sui Name Service";
    if (label === "The Move Book") return "Search results from The Move Book";
    if (label === "SDKs") return "Search results from the Sui ecosystem SDKs";
    if (label === "Walrus")
      return "Search results from the Walrus decentralized storage platform";
    if (label === "Seal") return "Search results from the Seal docs";
    return `Search results from ${label}`;
  };
  return (
    <div className="mb-4 flex justify-start border-2 border-solid border-white rounded-t-lg dark:bg-black dark:border-sui-black border-b-sui-gray-50 dark:border-b-sui-gray-80">
      {tabs.map(({ label, indexName, count }) => (
        <div className="relative group inline-block" key={indexName}>
          <button
            className={`mr-4 flex items-center font-semibold text-sm lg:text-md xl:text-lg bg-white dark:bg-sui-black cursor-pointer dark:text-sui-gray-45 ${activeTab === indexName ? "text-sui-disabled/100 font-bold border-2 border-solid border-transparent border-b-sui-blue-dark dark:border-b-sui-blue" : "border-transparent text-sui-disabled/70"}`}
            onClick={() => onChange(indexName)}
          >
            {label}{" "}
            <span
              className={`dark:text-sui-gray-90 text-xs rounded-full ml-1 py-1 px-2 border border-solid ${activeTab === indexName ? "dark:!text-sui-gray-45 bg-transparent border-sui-gray-3s dark:border-sui-gray-50" : "bg-sui-gray-45 border-transparent"}`}
            >
              {count}
            </span>
          </button>
          {showTooltips && (
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-max max-w-xs px-2 py-1 text-sm text-white bg-gray-800 rounded tooltip-delay">
              {tooltipFor(label)}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { imageTagSummariesPath } from "./api-paths.js";
import type { AnchoreClient } from "./client.js";
import {
  DEFAULT_RESOLUTION_LIST_CAPS,
  type ListImagesPageCaps,
} from "./list-images-pages.js";

const MAX_PAGE_LIMIT = 1_000;

export type FetchAllImageTagSummaryPagesResult = {
  rows: unknown[];
  pagesFetched: number;
  enumerationIncomplete: boolean;
  incompleteReason?: string;
};

function positiveInteger(value: string | null): number | undefined {
  if (value === null || !/^\d+$/.test(value)) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function finiteBoundedCap(value: number, hardMax: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }
  return Math.min(Math.floor(value), hardMax);
}

function totalRowsFromBody(data: unknown): number | undefined {
  if (data === null || typeof data !== "object") {
    return undefined;
  }
  const totalRows = (data as Record<string, unknown>).total_rows;
  return typeof totalRows === "number" &&
    Number.isSafeInteger(totalRows) &&
    totalRows >= 0
    ? totalRows
    : undefined;
}

function itemsFromBody(data: unknown): unknown[] {
  if (data === null || typeof data !== "object") {
    return [];
  }
  const items = (data as Record<string, unknown>).items;
  return Array.isArray(items) ? items : [];
}

/**
 * Walk `/summaries/image-tags` using its documented page/limit contract.
 * Missing `total_rows` is handled conservatively by continuing full pages until
 * a short or empty page, while both request and collected-row counts stay bounded.
 */
export async function fetchAllImageTagSummaryPages(
  client: AnchoreClient,
  connection: ResolvedAnchoreConnection,
  baseParams: URLSearchParams,
  caps: ListImagesPageCaps,
): Promise<FetchAllImageTagSummaryPagesResult> {
  const requestedLimit = positiveInteger(baseParams.get("limit"));
  const itemCap = finiteBoundedCap(
    caps.maxItems,
    DEFAULT_RESOLUTION_LIST_CAPS.maxItems,
  );
  const pageCap = finiteBoundedCap(
    caps.maxPages,
    DEFAULT_RESOLUTION_LIST_CAPS.maxPages,
  );
  const pageLimit = Math.max(
    1,
    Math.min(requestedLimit ?? MAX_PAGE_LIMIT, MAX_PAGE_LIMIT, Math.max(1, itemCap)),
  );
  const rows: unknown[] = [];
  let pagesFetched = 0;

  while (pagesFetched < pageCap) {
    const params = new URLSearchParams(baseParams);
    params.set("page", String(pagesFetched + 1));
    params.set("limit", String(pageLimit));
    const { data } = await client.getJsonWithByteLengthAndHeaders<unknown>(
      imageTagSummariesPath(connection.apiVersion, params),
    );
    pagesFetched += 1;

    const pageRows = itemsFromBody(data);
    const totalRows = totalRowsFromBody(data);
    const remaining = Math.max(0, itemCap - rows.length);
    rows.push(...pageRows.slice(0, remaining));

    const knownRowsRemain = totalRows !== undefined && rows.length < totalRows;
    const pageWasTruncated = pageRows.length > remaining;
    if (pageWasTruncated || (rows.length >= itemCap && knownRowsRemain)) {
      return {
        rows,
        pagesFetched,
        enumerationIncomplete: true,
        incompleteReason: `Stopped after collecting ${itemCap} image tag summary row(s) (maxItems cap).`,
      };
    }

    if (totalRows !== undefined) {
      if (!knownRowsRemain) {
        return { rows, pagesFetched, enumerationIncomplete: false };
      }
      if (pageRows.length === 0) {
        return {
          rows,
          pagesFetched,
          enumerationIncomplete: true,
          incompleteReason: "Image tag summary enumeration ended before total_rows was reached.",
        };
      }
    } else if (pageRows.length < pageLimit) {
      return { rows, pagesFetched, enumerationIncomplete: false };
    }

    if (pagesFetched >= pageCap) {
      return {
        rows,
        pagesFetched,
        enumerationIncomplete: true,
        incompleteReason: `Stopped after ${pageCap} page request(s) (maxPages cap).`,
      };
    }
  }

  return {
    rows,
    pagesFetched,
    enumerationIncomplete: true,
    incompleteReason: `Stopped after ${pageCap} page request(s) (maxPages cap).`,
  };
}

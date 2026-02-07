import { createWriteStream } from "node:fs";
import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { ensureCacheDir, getCachedPath, isCached } from "./cache.js";
import type { Registry } from "./types.js";

export interface ExtensionMetadata {
  extensionId: string;
  publisher: string;
  name: string;
  version: string;
  displayName?: string;
  description?: string;
  installCount?: number;
  lastUpdated?: string;
  registry?: Registry;
}

export interface DownloadOptions {
  destDir?: string;
  useCache?: boolean;
  forceDownload?: boolean;
}

export interface DownloadResult {
  path: string;
  metadata: ExtensionMetadata;
  fromCache?: boolean;
}

interface GalleryExtension {
  publisher: { publisherName: string };
  extensionName: string;
  displayName?: string;
  shortDescription?: string;
  versions: Array<{
    version: string;
    lastUpdated: string;
    files: Array<{ assetType: string; source: string }>;
  }>;
  statistics?: Array<{ statisticName: string; value: number }>;
}

interface GalleryResponse {
  results: Array<{
    extensions: GalleryExtension[];
  }>;
}

const GALLERY_API_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";

const GALLERY_API_VERSION = "7.1-preview.1";

const OPENVSX_API_URL = "https://open-vsx.org/api";

const CURSOR_API_URL = "https://marketplace.cursorapi.com/_apis/public/gallery/extensionquery";

interface OpenVSXExtension {
  namespace: string;
  name: string;
  displayName?: string;
  description?: string;
  version: string;
  timestamp?: string;
  downloadCount?: number;
  files?: {
    download?: string;
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validate that an API response matches the GalleryResponse shape.
 * Throws with a descriptive message when the response structure
 * is unexpected.
 */
function validateGalleryResponse(data: unknown, registryName: string): GalleryResponse {
  if (!isRecord(data)) {
    throw new Error(
      `Unexpected response from ${registryName}: ` + `expected object, got ${typeof data}`,
    );
  }

  const results = data["results"];
  if (!Array.isArray(results)) {
    throw new Error(`Unexpected response from ${registryName}: ` + "missing results array");
  }

  if (results.length === 0) {
    throw new Error(`Unexpected response from ${registryName}: ` + "results array is empty");
  }

  const firstResult: unknown = results[0];
  if (!isRecord(firstResult)) {
    throw new Error(`Unexpected response from ${registryName}: ` + "results[0] is not an object");
  }

  if (!Array.isArray(firstResult["extensions"])) {
    throw new Error(`Unexpected response from ${registryName}: ` + "missing extensions array");
  }

  return data as unknown as GalleryResponse;
}

/**
 * Validate that an API response matches the OpenVSXExtension shape.
 * Checks that required fields (namespace, name, version) exist and
 * are strings.
 */
function validateOpenVSXResponse(data: unknown): OpenVSXExtension {
  if (!isRecord(data)) {
    throw new Error("Unexpected response from OpenVSX: " + `expected object, got ${typeof data}`);
  }

  if (typeof data["namespace"] !== "string" || data["namespace"] === "") {
    throw new Error("Unexpected response from OpenVSX: " + "missing or invalid namespace field");
  }

  if (typeof data["name"] !== "string" || data["name"] === "") {
    throw new Error("Unexpected response from OpenVSX: " + "missing or invalid name field");
  }

  if (typeof data["version"] !== "string" || data["version"] === "") {
    throw new Error("Unexpected response from OpenVSX: " + "missing or invalid version field");
  }

  return data as unknown as OpenVSXExtension;
}

export interface ParsedExtensionId {
  publisher: string;
  name: string;
  version?: string;
  registry: Registry;
}

/**
 * Parse an extension ID in the format "publisher.name" or "publisher.name@version"
 * Optionally with registry prefix: "openvsx:publisher.name" or "marketplace:publisher.name"
 */
export function parseExtensionId(input: string): ParsedExtensionId {
  let registry: Registry = "marketplace";
  let rest = input;

  // Check for registry prefix
  if (input.startsWith("openvsx:")) {
    registry = "openvsx";
    rest = input.slice(8);
  } else if (input.startsWith("marketplace:")) {
    registry = "marketplace";
    rest = input.slice(12);
  } else if (input.startsWith("cursor:")) {
    registry = "cursor";
    rest = input.slice(7);
  }

  // Check for version suffix
  const atIndex = rest.lastIndexOf("@");
  let identifier = rest;
  let version: string | undefined;

  if (atIndex > 0) {
    identifier = rest.slice(0, atIndex);
    version = rest.slice(atIndex + 1);
  }

  // Split publisher.name
  const dotIndex = identifier.indexOf(".");
  if (dotIndex <= 0) {
    throw new Error(
      `Invalid extension ID: "${input}". Expected format: publisher.name or publisher.name@version`,
    );
  }

  const publisher = identifier.slice(0, dotIndex);
  const name = identifier.slice(dotIndex + 1);

  if (!publisher || !name) {
    throw new Error(
      `Invalid extension ID: "${input}". Expected format: publisher.name or publisher.name@version`,
    );
  }

  const result: ParsedExtensionId = { publisher, name, registry };
  if (version !== undefined) {
    result.version = version;
  }
  return result;
}

/**
 * Query the VS Code Marketplace for extension metadata
 */
export async function queryExtension(
  publisher: string,
  name: string,
  version?: string,
): Promise<ExtensionMetadata> {
  const extensionId = `${publisher}.${name}`;

  const requestBody = {
    filters: [
      {
        criteria: [{ filterType: 7, value: extensionId }],
        pageSize: 1,
        pageNumber: 1,
      },
    ],
    flags: 0x200 | 0x80 | 0x1, // Include versions, files, and statistics
  };

  const response = await fetch(GALLERY_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: `application/json;api-version=${GALLERY_API_VERSION}`,
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(`Marketplace API error: ${response.status} ${response.statusText}`);
  }

  const data = validateGalleryResponse(await response.json(), "VS Code Marketplace");
  const ext = data.results[0]?.extensions[0];

  if (!ext) {
    throw new Error(`Extension not found: ${extensionId}`);
  }

  const versions = ext.versions ?? [];

  // Find the requested version or use latest
  let targetVersion = versions[0];
  if (version) {
    const found = versions.find((v) => v.version === version);
    if (!found) {
      throw new Error(
        `Version ${version} not found for ${extensionId}. Latest: ${versions[0]?.version}`,
      );
    }
    targetVersion = found;
  }

  if (!targetVersion) {
    throw new Error(`No versions available for ${extensionId}`);
  }

  // Get install count from statistics
  const installStat = ext.statistics?.find((s) => s.statisticName === "install");

  const result: ExtensionMetadata = {
    extensionId,
    publisher: ext.publisher.publisherName,
    name: ext.extensionName,
    version: targetVersion.version,
    lastUpdated: targetVersion.lastUpdated,
    registry: "marketplace",
  };

  if (ext.displayName) {
    result.displayName = ext.displayName;
  }
  if (ext.shortDescription) {
    result.description = ext.shortDescription;
  }
  if (installStat?.value !== undefined) {
    result.installCount = installStat.value;
  }

  return result;
}

/**
 * Query OpenVSX for extension metadata
 */
export async function queryOpenVSX(
  publisher: string,
  name: string,
  version?: string,
): Promise<ExtensionMetadata> {
  const extensionId = `${publisher}.${name}`;
  const url = version
    ? `${OPENVSX_API_URL}/${publisher}/${name}/${version}`
    : `${OPENVSX_API_URL}/${publisher}/${name}`;

  const response = await fetch(url);
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Extension not found on OpenVSX: ${extensionId}`);
    }
    throw new Error(`OpenVSX API error: ${response.status} ${response.statusText}`);
  }

  const data = validateOpenVSXResponse(await response.json());

  const result: ExtensionMetadata = {
    extensionId,
    publisher: data.namespace,
    name: data.name,
    version: data.version,
    registry: "openvsx",
  };

  if (data.timestamp) {
    result.lastUpdated = data.timestamp;
  }
  if (data.displayName) {
    result.displayName = data.displayName;
  }
  if (data.description) {
    result.description = data.description;
  }
  if (data.downloadCount !== undefined) {
    result.installCount = data.downloadCount;
  }

  return result;
}

/**
 * Query Cursor Extension Marketplace for extension metadata
 */
export async function queryCursor(
  publisher: string,
  name: string,
  version?: string,
): Promise<ExtensionMetadata> {
  const extensionId = `${publisher}.${name}`;

  const requestBody = {
    filters: [
      {
        criteria: [{ filterType: 7, value: extensionId }],
        pageSize: 1,
        pageNumber: 1,
      },
    ],
    flags: 0x200 | 0x80 | 0x1, // Include versions, files, and statistics
  };

  const response = await fetch(CURSOR_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: `application/json;api-version=${GALLERY_API_VERSION}`,
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(`Cursor API error: ${response.status} ${response.statusText}`);
  }

  const data = validateGalleryResponse(await response.json(), "Cursor Marketplace");
  const ext = data.results[0]?.extensions[0];

  if (!ext) {
    throw new Error(`Extension not found on Cursor: ${extensionId}`);
  }

  const versions = ext.versions ?? [];

  // Find the requested version or use latest
  let targetVersion = versions[0];
  if (version) {
    const found = versions.find((v) => v.version === version);
    if (!found) {
      throw new Error(
        `Version ${version} not found for ${extensionId}. Latest: ${versions[0]?.version}`,
      );
    }
    targetVersion = found;
  }

  if (!targetVersion) {
    throw new Error(`No versions available for ${extensionId}`);
  }

  // Get install count from statistics
  const installStat = ext.statistics?.find((s) => s.statisticName === "install");

  const result: ExtensionMetadata = {
    extensionId,
    publisher: ext.publisher.publisherName,
    name: ext.extensionName,
    version: targetVersion.version,
    lastUpdated: targetVersion.lastUpdated,
    registry: "cursor",
  };

  if (ext.displayName) {
    result.displayName = ext.displayName;
  }
  if (ext.shortDescription) {
    result.description = ext.shortDescription;
  }
  if (installStat?.value !== undefined) {
    result.installCount = installStat.value;
  }

  return result;
}

/**
 * Get the download URL for a VSIX package from the VS Code Marketplace
 */
export function getMarketplaceDownloadUrl(
  publisher: string,
  name: string,
  version: string,
): string {
  return `https://${publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/${publisher}/extension/${name}/${version}/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage`;
}

/**
 * Get the download URL for a VSIX package from OpenVSX
 */
export function getOpenVSXDownloadUrl(publisher: string, name: string, version: string): string {
  return `${OPENVSX_API_URL}/${publisher}/${name}/${version}/file/${publisher}.${name}-${version}.vsix`;
}

/**
 * Get the download URL for a VSIX package from Cursor Extension Marketplace
 */
export function getCursorDownloadUrl(publisher: string, name: string, version: string): string {
  return `https://marketplace.cursorapi.com/_apis/public/gallery/publishers/${publisher}/vsextensions/${name}/${version}/vspackage`;
}

/**
 * Get the download URL for a VSIX package
 * @deprecated Use getMarketplaceDownloadUrl or getOpenVSXDownloadUrl instead
 */
export function getDownloadUrl(publisher: string, name: string, version: string): string {
  return getMarketplaceDownloadUrl(publisher, name, version);
}

/**
 * Download a VSIX from a URL
 */
async function downloadVsixFromUrl(url: string, destPath: string): Promise<void> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Download failed: ${response.status} ${response.statusText}`);
  }

  if (!response.body) {
    throw new Error("Empty response body");
  }

  // Ensure destination directory exists
  await mkdir(dirname(destPath), { recursive: true });

  // Stream the response to a file
  const nodeStream = Readable.fromWeb(response.body as import("node:stream/web").ReadableStream);
  const fileStream = createWriteStream(destPath);

  await pipeline(nodeStream, fileStream);
}

/**
 * Download a VSIX from the marketplace
 */
export async function downloadVsix(
  publisher: string,
  name: string,
  version: string,
  destPath: string,
  registry: Registry = "marketplace",
): Promise<void> {
  let url: string;
  if (registry === "openvsx") {
    url = getOpenVSXDownloadUrl(publisher, name, version);
  } else if (registry === "cursor") {
    url = getCursorDownloadUrl(publisher, name, version);
  } else {
    url = getMarketplaceDownloadUrl(publisher, name, version);
  }

  await downloadVsixFromUrl(url, destPath);
}

/**
 * Download an extension from the VS Code Marketplace or OpenVSX
 *
 * @param extensionId - Extension ID in format "publisher.name", "publisher.name@version",
 *                      or with registry prefix: "openvsx:publisher.name", "marketplace:publisher.name"
 * @param options - Optional settings
 * @returns Path to downloaded VSIX and extension metadata
 */
export async function downloadExtension(
  extensionId: string,
  options?: DownloadOptions,
): Promise<DownloadResult> {
  const { publisher, name, version, registry } = parseExtensionId(extensionId);
  const useCache = options?.useCache !== false;
  const forceDownload = options?.forceDownload === true;

  // Query the appropriate registry for metadata
  let metadata: ExtensionMetadata;
  if (registry === "openvsx") {
    metadata = await queryOpenVSX(publisher, name, version);
  } else if (registry === "cursor") {
    metadata = await queryCursor(publisher, name, version);
  } else {
    metadata = await queryExtension(publisher, name, version);
  }

  // If destDir is explicitly provided, download directly there (bypasses cache)
  if (options?.destDir) {
    const filename = `${metadata.publisher}.${metadata.name}-${metadata.version}.vsix`;
    const destPath = join(options.destDir, filename);

    // Check cache first if enabled
    if (useCache && !forceDownload) {
      const cachedPath = getCachedPath(
        registry,
        metadata.publisher,
        metadata.name,
        metadata.version,
      );
      const cached = await isCached(registry, metadata.publisher, metadata.name, metadata.version);

      if (cached) {
        // Copy from cache to destination
        await mkdir(options.destDir, { recursive: true });
        await copyFile(cachedPath, destPath);
        return { path: destPath, metadata, fromCache: true };
      }
    }

    // Download fresh
    await downloadVsix(metadata.publisher, metadata.name, metadata.version, destPath, registry);
    return { path: destPath, metadata, fromCache: false };
  }

  // Use cache directory
  const cachedPath = getCachedPath(registry, metadata.publisher, metadata.name, metadata.version);

  // Check if already cached
  if (useCache && !forceDownload) {
    const cached = await isCached(registry, metadata.publisher, metadata.name, metadata.version);
    if (cached) {
      return { path: cachedPath, metadata, fromCache: true };
    }
  }

  // Download to cache
  await ensureCacheDir(registry);
  await downloadVsix(metadata.publisher, metadata.name, metadata.version, cachedPath, registry);

  return { path: cachedPath, metadata, fromCache: false };
}

import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
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

export interface DownloadResult {
  path: string;
  metadata: ExtensionMetadata;
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

  const data = (await response.json()) as GalleryResponse;
  const extensions = data.results?.[0]?.extensions;
  const ext = extensions?.[0];

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

  const data = (await response.json()) as OpenVSXExtension;

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
  const url =
    registry === "openvsx"
      ? getOpenVSXDownloadUrl(publisher, name, version)
      : getMarketplaceDownloadUrl(publisher, name, version);

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
  options?: { destDir?: string },
): Promise<DownloadResult> {
  const { publisher, name, version, registry } = parseExtensionId(extensionId);

  // Query the appropriate registry for metadata
  const metadata =
    registry === "openvsx"
      ? await queryOpenVSX(publisher, name, version)
      : await queryExtension(publisher, name, version);

  // Determine download path
  const destDir = options?.destDir ?? process.cwd();
  const filename = `${metadata.publisher}.${metadata.name}-${metadata.version}.vsix`;
  const destPath = join(destDir, filename);

  // Download the VSIX
  await downloadVsix(metadata.publisher, metadata.name, metadata.version, destPath, registry);

  return {
    path: destPath,
    metadata,
  };
}

import type { VsixManifest } from "#internal/scanner/types.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalidField(source: string, field: string, expected: string): Error {
  return new Error(`Cannot load ${source}: ${field} must be ${expected}. Repair package.json.`);
}

function validateStrings(value: Record<string, unknown>, source: string): void {
  for (const field of ["name", "version"]) {
    if (typeof value[field] !== "string" || value[field] === "") {
      throw invalidField(source, field, "a non-empty string");
    }
  }
  for (const field of ["publisher", "displayName", "description", "main", "browser"]) {
    if (value[field] !== undefined && typeof value[field] !== "string") {
      throw invalidField(source, field, "a string");
    }
  }
}

function validateLists(value: Record<string, unknown>, source: string): void {
  for (const field of ["activationEvents", "extensionDependencies"]) {
    const list = value[field];
    if (
      list !== undefined &&
      (!Array.isArray(list) || !list.every((item) => typeof item === "string"))
    ) {
      throw invalidField(source, field, "an array of strings");
    }
  }
}

function validateRecords(value: Record<string, unknown>, source: string): void {
  for (const field of ["dependencies", "devDependencies", "scripts"]) {
    const record = value[field];
    if (
      record !== undefined &&
      (!isRecord(record) || !Object.values(record).every((item) => typeof item === "string"))
    ) {
      throw invalidField(source, field, "an object with string values");
    }
  }
}

function validateContributionEntries(entries: unknown, source: string, field: string): void {
  if (entries === undefined) return;
  if (!Array.isArray(entries)) throw invalidField(source, `contributes.${field}`, "an array");
  for (const entry of entries) {
    if (!isRecord(entry)) throw invalidField(source, `contributes.${field}`, "an array of objects");
    for (const key of ["id", "label", "path"]) {
      if (entry[key] !== undefined && typeof entry[key] !== "string") {
        throw invalidField(source, `contributes.${field}.${key}`, "a string");
      }
    }
  }
}

function validateContributions(value: unknown, source: string): void {
  if (value === undefined) return;
  if (!isRecord(value)) throw invalidField(source, "contributes", "an object");
  for (const field of ["themes", "iconThemes"])
    validateContributionEntries(value[field], source, field);
}

/** Parse extension package metadata once and validate the fields consumed by checks. */
export function parseManifest(buffer: Buffer, source: string): VsixManifest {
  let value: unknown;
  try {
    value = JSON.parse(buffer.toString("utf8"));
  } catch (error) {
    throw new Error(`Cannot parse ${source}: repair package.json JSON.`, { cause: error });
  }
  if (!isRecord(value)) throw invalidField(source, "package.json", "an object");
  validateStrings(value, source);
  validateLists(value, source);
  validateRecords(value, source);
  validateContributions(value["contributes"], source);
  return value as unknown as VsixManifest;
}

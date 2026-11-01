import { crc32, deflateRawSync } from "node:zlib";

interface ZipEntry {
  name: string;
  content: string;
  rawName?: Buffer;
  extraFields?: Buffer;
  utf8Name?: boolean;
  stored?: boolean;
}

function localHeader(name: Buffer, extra: Buffer, flags: number, method: number): Buffer {
  const header = Buffer.alloc(30 + name.length + extra.length);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(flags, 6);
  header.writeUInt16LE(method, 8);
  header.writeUInt16LE(name.length, 26);
  header.writeUInt16LE(extra.length, 28);
  name.copy(header, 30);
  extra.copy(header, 30 + name.length);
  return header;
}

function centralHeader(local: Buffer, offset: number): Buffer {
  const header = Buffer.alloc(local.length + 16);
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(20, 4);
  local.copy(header, 6, 4, 30);
  header.writeUInt32LE(offset, 42);
  local.copy(header, 46, 30);
  return header;
}

function endRecord(count: number, size: number, offset: number): Buffer {
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(count, 8);
  end.writeUInt16LE(count, 10);
  end.writeUInt32LE(size, 12);
  end.writeUInt32LE(offset, 16);
  return end;
}

function prepareEntry(
  file: ZipEntry,
  dataDescriptor: boolean,
): { local: Buffer; compressed: Buffer } {
  const content = Buffer.from(file.content);
  const compressed = file.stored === true ? content : deflateRawSync(content);
  const name = file.rawName ?? Buffer.from(file.name);
  const flags = (dataDescriptor ? 8 : 0) | (file.utf8Name === false ? 0 : 0x800);
  const local = localHeader(
    name,
    file.extraFields ?? Buffer.alloc(0),
    flags,
    file.stored === true ? 0 : 8,
  );
  local.writeUInt32LE(crc32(content), 14);
  local.writeUInt32LE(compressed.length, 18);
  local.writeUInt32LE(content.length, 22);
  return { local, compressed };
}

/** Build valid test archives; tests that forge inconsistent headers keep their own builders. */
export function createTestZip(
  files: ZipEntry[],
  options: { useDataDescriptor?: boolean } = {},
): Buffer {
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const file of files) {
    const { local, compressed } = prepareEntry(file, options.useDataDescriptor === true);
    central.push(centralHeader(local, offset));
    chunks.push(local, compressed);
    offset += local.length + compressed.length;
    if (options.useDataDescriptor === true) {
      const descriptor = Buffer.alloc(16);
      descriptor.writeUInt32LE(0x08074b50, 0);
      local.copy(descriptor, 4, 14, 26);
      local.fill(0, 14, 26);
      chunks.push(descriptor);
      offset += descriptor.length;
    }
  }
  return Buffer.concat([
    ...chunks,
    ...central,
    endRecord(
      files.length,
      central.reduce((size, entry) => size + entry.length, 0),
      offset,
    ),
  ]);
}

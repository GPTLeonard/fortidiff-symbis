export type FgBlock = {
  header: string;
  start: number;
  end: number;
  lines: string[];
};

export type FgEdit = {
  name: string;
  start: number;
  end: number;
  lines: string[];
};

export type ConfigIndex = {
  text: string;
  textLower: string;
  lines: string[];
  blocks: FgBlock[];
  blocksByHeader: Map<string, FgBlock[]>;
};

export type ConfigHeader = {
  model: string | null;
  version: string | null;
  passwordMask: boolean | null;
  raw: string | null;
};

export function createConfigIndex(text: string): ConfigIndex {
  const lines = text.split(/\r?\n/);
  const blocks = parseBlocks(lines);
  const blocksByHeader = new Map<string, FgBlock[]>();
  for (const block of blocks) {
    const list = blocksByHeader.get(block.header) ?? [];
    list.push(block);
    blocksByHeader.set(block.header, list);
  }

  return {
    text,
    textLower: text.toLowerCase(),
    lines,
    blocks,
    blocksByHeader,
  };
}

export function parseConfigHeader(text: string): ConfigHeader {
  const lines = text.split(/\r?\n/);
  const headerMatch = text.match(/#config-version=([^:-\s]+)-([0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
  const maskMatch = text.match(/#password_mask\s*=\s*(\d+)/);

  let headerLine: string | null = headerMatch ? headerMatch[0] : null;
  let maskLine: string | null = maskMatch ? maskMatch[0] : null;

  if (!headerLine || !maskLine) {
    for (const line of lines) {
      const cleaned = line.replace(/^\uFEFF/, "").trim();
      if (!headerLine && cleaned.includes("#config-version=")) {
        headerLine = cleaned;
      }
      if (!maskLine && cleaned.includes("#password_mask=")) {
        maskLine = cleaned;
      }
      if (headerLine && maskLine) break;
    }
  }

  let model: string | null = null;
  let version: string | null = null;

  if (headerMatch) {
    model = headerMatch[1] || null;
    version = headerMatch[2] || null;
  } else if (headerLine) {
    const trimmed = headerLine.replace(/^\uFEFF/, "").trim();
    const match = trimmed.match(/#config-version=([^:-]+)-([0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
    if (match) {
      model = match[1] || null;
      version = match[2] || null;
    }
  }

  let passwordMask: boolean | null = null;
  if (maskMatch) {
    passwordMask = maskMatch[1] === "1";
  } else if (maskLine) {
    const trimmed = maskLine.replace(/^\uFEFF/, "").trim();
    const match = trimmed.match(/#password_mask\s*=\s*(\d+)/);
    if (match) {
      passwordMask = match[1] === "1";
    }
  }

  return {
    model,
    version,
    passwordMask,
    raw: headerLine,
  };
}

export function parseBlocks(lines: string[]): FgBlock[] {
  const blocks: FgBlock[] = [];
  let current: FgBlock | null = null;
  let depth = 0;

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("config ")) {
      if (!current) {
        current = { header: trimmed, start: index, end: index, lines: [line] };
        depth = 1;
      } else {
        depth += 1;
        current.lines.push(line);
        current.end = index;
      }
      return;
    }

    if (current) {
      current.lines.push(line);
      current.end = index;
      if (trimmed === "end") {
        depth -= 1;
        if (depth === 0) {
          blocks.push(current);
          current = null;
        }
      }
    }
  });

  if (current) {
    blocks.push(current);
  }

  return blocks;
}

export function findBlock(index: ConfigIndex, header: string): FgBlock | null {
  const matches = index.blocksByHeader.get(header);
  if (!matches || matches.length === 0) return null;
  return matches[0];
}

export function findBlocksByPrefix(index: ConfigIndex, prefix: string): FgBlock[] {
  const matches: FgBlock[] = [];
  for (const block of index.blocks) {
    if (block.header.startsWith(prefix)) {
      matches.push(block);
    }
  }
  return matches;
}

export function parseEdits(block: FgBlock): FgEdit[] {
  const edits: FgEdit[] = [];
  let current: FgEdit | null = null;

  block.lines.forEach((line, offset) => {
    const trimmed = line.trim();
    const absoluteIndex = block.start + offset;
    if (trimmed.startsWith("edit ")) {
      if (current) {
        edits.push(current);
      }
      current = {
        name: trimmed.replace(/^edit\s+/, "").replace(/^\"|\"$/g, ""),
        start: absoluteIndex,
        end: absoluteIndex,
        lines: [line],
      };
      return;
    }

    if (current) {
      current.lines.push(line);
      current.end = absoluteIndex;
      if (trimmed === "next") {
        edits.push(current);
        current = null;
      }
    }
  });

  if (current) {
    edits.push(current);
  }

  return edits;
}

export function findLineIndex(lines: string[], matcher: RegExp, start = 0, end = lines.length - 1): number {
  const safeEnd = Math.min(end, lines.length - 1);
  for (let i = start; i <= safeEnd; i += 1) {
    if (matcher.test(lines[i])) {
      return i;
    }
  }
  return -1;
}

export function makeSnippet(lines: string[], start: number, end: number, pad = 3, maxLines = 80): string {
  const sliceStart = Math.max(0, start - pad);
  const sliceEnd = Math.min(lines.length - 1, end + pad);
  const slice = lines.slice(sliceStart, sliceEnd + 1);
  if (slice.length <= maxLines) return slice.join("\n");
  const head = slice.slice(0, Math.floor(maxLines / 2));
  const tail = slice.slice(slice.length - Math.floor(maxLines / 2));
  return [...head, "...", ...tail].join("\n");
}

export function getBlockSnippet(index: ConfigIndex, block: FgBlock | null, maxLines = 80): string {
  if (!block) return "";
  return makeSnippet(index.lines, block.start, block.end, 0, maxLines);
}

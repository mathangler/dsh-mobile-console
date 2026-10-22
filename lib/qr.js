/**
 * dsh-mobile-console — QR encoder (byte mode, versions 1–10, all EC levels).
 *
 * Why hand-written: this plugin ships with no dependencies at all, and the
 * whole DeepSeek Harness installation contains no QR library. The pairing URL
 * carries a per-process launch token, so it must never be handed to an online
 * QR image service.
 *
 * Scope: byte mode (UTF-8) only, versions 1–10, error-correction levels L/M/Q/H,
 * all eight masks with the standard penalty scoring. That covers every entry URL
 * this plugin produces (the EC level M ceiling is 213 bytes at version 10) while
 * staying small enough to audit. Version information (required from version 7)
 * is implemented; no ECI, kanji, numeric or alphanumeric modes.
 *
 * The algorithm follows the published QR Code specification (ISO/IEC 18004):
 * Reed–Solomon over GF(256) with the primitive polynomial 0x11D, the standard
 * block split, the zigzag module placement, and the four penalty rules.
 *
 * @module dsh-mobile-console/qr
 */

/** Error-correction levels in the order the format bits encode them. */
const EC_LEVELS = { L: 0, M: 1, Q: 2, H: 3 };

/** Format-bit value per level: L=1, M=0, Q=3, H=2 (ISO/IEC 18004 table 25). */
const EC_FORMAT_BITS = { L: 1, M: 0, Q: 3, H: 2 };

/** Highest version this encoder builds; keeps the tables small and auditable. */
const MAX_VERSION = 10;

/**
 * Error-correction codewords per block, indexed by version.
 * Row order: L, M, Q, H. Index 0 is unused.
 */
const ECC_CODEWORDS_PER_BLOCK = {
  L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
  M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26],
  Q: [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24],
  H: [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28],
};

/**
 * Number of error-correction blocks, indexed by version.
 * Row order: L, M, Q, H. Index 0 is unused.
 */
const NUM_EC_BLOCKS = {
  L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
  M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5],
  Q: [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8],
  H: [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8],
};

/**
 * Data modules available in a version before function patterns are placed.
 * @param version - QR version, 1–40 (this encoder builds up to 10).
 * @returns module count, always a multiple of 8 for a whole codeword count.
 */
function rawDataModules(version) {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

/** Total codewords (data + error correction) of one version. */
function totalCodewords(version) {
  return Math.floor(rawDataModules(version) / 8);
}

/** Data codewords of one version and level. */
function dataCodewords(version, level) {
  return (
    totalCodewords(version) -
    ECC_CODEWORDS_PER_BLOCK[level][version] * NUM_EC_BLOCKS[level][version]
  );
}

/** Character-count field width in bits for byte mode. */
function byteCountBits(version) {
  return version <= 9 ? 8 : 16;
}

/** Alignment-pattern centre coordinates for one version (empty at version 1). */
function alignmentPatternPositions(version) {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = version * 4 + 10; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

// ── Reed–Solomon over GF(256), primitive polynomial 0x11D ────────────────────

/** Multiply two GF(256) field elements. */
function gfMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

/**
 * Generator polynomial of the given degree, highest power first, with the
 * leading coefficient omitted (it is always 1).
 */
function reedSolomonDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMultiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

/** Remainder of `data` divided by `divisor`, i.e. the block's EC codewords. */
function reedSolomonRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < result.length; i++) result[i] ^= gfMultiply(divisor[i], factor);
  }
  return result;
}

// ── Bit buffer ───────────────────────────────────────────────────────────────

/** Append the low `length` bits of `value`, most significant bit first. */
function appendBits(buffer, value, length) {
  for (let i = length - 1; i >= 0; i--) buffer.push((value >>> i) & 1);
}

// ── Matrix construction ──────────────────────────────────────────────────────

/** Read one bit of a byte array, most significant bit first. */
function bitOf(bytes, index) {
  return ((bytes[index >>> 3] >>> (7 - (index & 7))) & 1) !== 0;
}

/** One mask predicate per mask id, in the specification's coordinate terms. */
const MASK_FUNCTIONS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

/**
 * Penalty score of one masked matrix (the four specification rules).
 * @param modules - square matrix of booleans, `modules[y][x]`.
 * @param size - matrix edge length.
 * @returns the score; the encoder keeps the mask with the lowest one.
 */
function penaltyScore(modules, size) {
  let score = 0;
  const runPenalty = (run, dark) => {
    void dark;
    return run >= 5 ? 3 + (run - 5) : 0;
  };

  // Rule 1: runs of five or more same-coloured modules in a row or column.
  for (let y = 0; y < size; y++) {
    let run = 1;
    for (let x = 1; x < size; x++) {
      if (modules[y][x] === modules[y][x - 1]) {
        run++;
      } else {
        score += runPenalty(run, modules[y][x - 1]);
        run = 1;
      }
    }
    score += runPenalty(run, modules[y][size - 1]);
  }
  for (let x = 0; x < size; x++) {
    let run = 1;
    for (let y = 1; y < size; y++) {
      if (modules[y][x] === modules[y - 1][x]) {
        run++;
      } else {
        score += runPenalty(run, modules[y - 1][x]);
        run = 1;
      }
    }
    score += runPenalty(run, modules[size - 1][x]);
  }

  // Rule 2: every 2×2 block of one colour.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) score += 3;
    }
  }

  // Rule 3: the 1:1:3:1:1 finder-like pattern with four light modules on a side.
  const patternA = [true, false, true, true, true, false, true, false, false, false, false];
  const patternB = [false, false, false, false, true, false, true, true, true, false, true];
  const matches = (get, start) => {
    for (let i = 0; i < 11; i++) if (get(start + i) !== patternA[i]) return false;
    return true;
  };
  const matchesB = (get, start) => {
    for (let i = 0; i < 11; i++) if (get(start + i) !== patternB[i]) return false;
    return true;
  };
  for (let y = 0; y < size; y++) {
    const row = (i) => modules[y][i];
    for (let x = 0; x + 11 <= size; x++) if (matches(row, x) || matchesB(row, x)) score += 40;
  }
  for (let x = 0; x < size; x++) {
    const col = (i) => modules[i][x];
    for (let y = 0; y + 11 <= size; y++) if (matches(col, y) || matchesB(col, y)) score += 40;
  }

  // Rule 4: deviation of the dark-module proportion from 50%.
  let dark = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (modules[y][x]) dark++;
  const total = size * size;
  const k = Math.floor(Math.abs((dark * 100) / total - 50) / 5);
  score += k * 10;

  return score;
}

/** Allocate a `size`×`size` boolean matrix filled with false. */
function emptyMatrix(size) {
  const rows = [];
  for (let y = 0; y < size; y++) rows.push(new Array(size).fill(false));
  return rows;
}

/**
 * Draw one finder pattern (7×7 plus its separator) with its top-left corner at
 * (x, y); the caller keeps it inside the matrix by construction.
 */
function drawFinder(modules, reserved, size, x, y) {
  for (let dy = -1; dy <= 7; dy++) {
    for (let dx = -1; dx <= 7; dx++) {
      const xx = x + dx;
      const yy = y + dy;
      if (xx < 0 || xx >= size || yy < 0 || yy >= size) continue;
      const dist = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
      modules[yy][xx] = dist !== 2 && dist <= 3;
      reserved[yy][xx] = true;
    }
  }
}

/** Draw one 5×5 alignment pattern centred at (x, y). */
function drawAlignment(modules, reserved, size, x, y) {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      modules[y + dy][x + dx] = dist !== 1;
      reserved[y + dy][x + dx] = true;
    }
  }
}

/** Write one function module: value plus reservation, ignoring coordinates. */
function setFunction(modules, reserved, x, y, dark) {
  modules[y][x] = dark;
  reserved[y][x] = true;
}

/** 15-bit format information for one level and mask (BCH(15,5) plus 0x5412). */
function formatBits(level, mask) {
  const data = (EC_FORMAT_BITS[level] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

/** 18-bit version information for versions 7 and above (BCH(18,6)). */
function versionBits(version) {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | rem;
}

/**
 * Encode text as a QR Code.
 *
 * @param text - the string to encode (UTF-8, byte mode).
 * @param options - `level` (`'L' | 'M' | 'Q' | 'H'`, default `'M'`) and an
 *   optional `minVersion` to force a larger symbol.
 * @returns `{ version, size, level, mask, bits }`, where `bits` is `size * size`
 *   characters of `'0'` (light) and `'1'` (dark), row-major.
 * @throws RangeError when the text does not fit version 10 at that level.
 */
export function encodeQr(text, options = {}) {
  const level = String(options.level ?? 'M').toUpperCase();
  if (!(level in EC_LEVELS)) throw new RangeError(`qr: unknown error-correction level ${JSON.stringify(level)}`);
  const bytes = new TextEncoder().encode(String(text));

  let version = Math.max(1, Number(options.minVersion) || 1);
  for (;;) {
    const capacity = dataCodewords(version, level) * 8;
    const needed = 4 + byteCountBits(version) + bytes.length * 8;
    if (needed <= capacity) break;
    version++;
    if (version > MAX_VERSION) {
      throw new RangeError(
        `qr: ${bytes.length} bytes do not fit version ${MAX_VERSION} at level ${level}`,
      );
    }
  }

  // ── Data codewords: mode, count, payload, terminator, pad bytes ────────────
  const capacityBits = dataCodewords(version, level) * 8;
  const bits = [];
  appendBits(bits, 0x4, 4);
  appendBits(bits, bytes.length, byteCountBits(version));
  for (const b of bytes) appendBits(bits, b, 8);
  appendBits(bits, 0, Math.min(4, capacityBits - bits.length));
  appendBits(bits, 0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacityBits; pad ^= 0xec ^ 0x11) appendBits(bits, pad, 8);
  const dataBytes = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i++) dataBytes[i >>> 3] |= bits[i] << (7 - (i & 7));

  // ── Block split, error correction, interleave ─────────────────────────────
  const numBlocks = NUM_EC_BLOCKS[level][version];
  const ecPerBlock = ECC_CODEWORDS_PER_BLOCK[level][version];
  const totalData = dataCodewords(version, level);
  const shortBlockLen = Math.floor(totalData / numBlocks);
  const numShortBlocks = numBlocks - (totalData % numBlocks);

  const divisor = reedSolomonDivisor(ecPerBlock);
  const dataBlocks = [];
  const ecBlocks = [];
  for (let i = 0, offset = 0; i < numBlocks; i++) {
    const len = shortBlockLen + (i < numShortBlocks ? 0 : 1);
    const block = dataBytes.subarray(offset, offset + len);
    offset += len;
    dataBlocks.push(block);
    ecBlocks.push(reedSolomonRemainder(block, divisor));
  }
  const interleaved = [];
  const maxDataLen = shortBlockLen + 1;
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < dataBlocks[b].length) interleaved.push(dataBlocks[b][i]);
    }
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (let b = 0; b < numBlocks; b++) interleaved.push(ecBlocks[b][i]);
  }
  const codewords = Uint8Array.from(interleaved);

  // ── Function patterns ─────────────────────────────────────────────────────
  const size = version * 4 + 17;
  const modules = emptyMatrix(size);
  const reserved = emptyMatrix(size);

  drawFinder(modules, reserved, size, 0, 0);
  drawFinder(modules, reserved, size, size - 7, 0);
  drawFinder(modules, reserved, size, 0, size - 7);

  for (let i = 8; i < size - 8; i++) {
    const dark = i % 2 === 0;
    setFunction(modules, reserved, i, 6, dark);
    setFunction(modules, reserved, 6, i, dark);
  }

  const align = alignmentPatternPositions(version);
  for (const ay of align) {
    for (const ax of align) {
      const corner =
        (ax === 6 && ay === 6) ||
        (ax === 6 && ay === size - 7) ||
        (ax === size - 7 && ay === 6);
      if (!corner) drawAlignment(modules, reserved, size, ax, ay);
    }
  }

  // Reserve the format areas and the always-dark module; values are written
  // after the mask is chosen.
  for (let i = 0; i <= 5; i++) setFunction(modules, reserved, 8, i, false);
  setFunction(modules, reserved, 8, 7, false);
  setFunction(modules, reserved, 8, 8, false);
  setFunction(modules, reserved, 7, 8, false);
  for (let i = 9; i < 15; i++) setFunction(modules, reserved, 14 - i, 8, false);
  for (let i = 0; i < 8; i++) setFunction(modules, reserved, size - 1 - i, 8, false);
  for (let i = 8; i < 15; i++) setFunction(modules, reserved, 8, size - 15 + i, false);
  // The always-dark module sits at (row 4V+9, column 8) — that is row size-8.
  setFunction(modules, reserved, 8, size - 8, true);

  if (version >= 7) {
    const vb = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((vb >>> i) & 1) !== 0;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFunction(modules, reserved, a, b, dark);
      setFunction(modules, reserved, b, a, dark);
    }
  }

  // ── Data placement (zigzag, right to left, skipping column 6) ─────────────
  const totalBits = codewords.length * 8;
  let index = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (reserved[y][x] || index >= totalBits) continue;
        modules[y][x] = bitOf(codewords, index);
        index++;
      }
    }
  }

  // ── Mask selection and format information ─────────────────────────────────
  // `forceMask` pins one mask instead of scoring all eight; it exists so the
  // test suite can compare this encoder against a reference implementation
  // mask by mask (a difference in penalty scoring alone would otherwise change
  // the chosen mask and hide a real encoding difference).
  const forced =
    Number.isInteger(options.forceMask) && options.forceMask >= 0 && options.forceMask <= 7
      ? options.forceMask
      : null;
  let bestMask = forced ?? 0;
  let bestScore = Number.POSITIVE_INFINITY;
  let bestMatrix = null;
  for (let mask = forced ?? 0; mask < (forced === null ? 8 : forced + 1); mask++) {
    const candidate = modules.map((row) => row.slice());
    const fn = MASK_FUNCTIONS[mask];
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (!reserved[y][x] && fn(x, y)) candidate[y][x] = !candidate[y][x];
      }
    }
    writeFormat(candidate, size, level, mask);
    const score = penaltyScore(candidate, size);
    if (score < bestScore) {
      bestScore = score;
      bestMask = mask;
      bestMatrix = candidate;
    }
  }

  let out = '';
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) out += bestMatrix[y][x] ? '1' : '0';
  }
  let reservedBits = '';
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) reservedBits += reserved[y][x] ? '1' : '0';
  }
  return {
    version,
    size,
    level,
    mask: bestMask,
    bits: out,
    reservedBits,
    codewords: Array.from(codewords),
    dataCodewordCount: totalData,
    ecCodewordsPerBlock: ecPerBlock,
    blockCount: numBlocks,
  };
}

/** Write both copies of the format information into an already-masked matrix. */
function writeFormat(modules, size, level, mask) {
  const bits = formatBits(level, mask);
  const bit = (i) => ((bits >>> i) & 1) !== 0;
  for (let i = 0; i <= 5; i++) modules[i][8] = bit(i);
  modules[7][8] = bit(6);
  modules[8][8] = bit(7);
  modules[8][7] = bit(8);
  for (let i = 9; i < 15; i++) modules[8][14 - i] = bit(i);
  for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = bit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = bit(i);
  modules[size - 8][8] = true;
}

const GF_EXP = new Array(512).fill(0);
const GF_LOG = new Array(256).fill(0);

(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x = (x << 1) ^ (x >= 128 ? 0x11D : 0);
    x &= 0xFF;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGenPoly(ecCount: number): number[] {
  let poly = [1];
  for (let i = 0; i < ecCount; i++) {
    const term = [1, GF_EXP[i]];
    const result = new Array(poly.length + term.length - 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      for (let k = 0; k < term.length; k++) {
        result[j + k] ^= gfMul(poly[j], term[k]);
      }
    }
    poly = result;
  }
  return poly;
}

function rsEncode(data: number[], ecCount: number): number[] {
  const gen = rsGenPoly(ecCount);
  const msg = [...data, ...new Array(ecCount).fill(0)];
  for (let i = 0; i < data.length; i++) {
    if (msg[i] !== 0) {
      const scale = GF_LOG[msg[i]];
      for (let j = 0; j < gen.length; j++) {
        msg[i + j] ^= GF_EXP[(GF_LOG[gen[j]] + scale) % 255];
      }
    }
  }
  return msg.slice(data.length);
}

const VERSION_TABLE: { ver: number; total: number; data: number; ec: number; blocks: number }[] = [
  { ver: 1, total: 26, data: 16, ec: 10, blocks: 1 },
  { ver: 2, total: 44, data: 28, ec: 16, blocks: 1 },
  { ver: 3, total: 70, data: 44, ec: 26, blocks: 1 },
  { ver: 4, total: 100, data: 64, ec: 36, blocks: 2 },
  { ver: 5, total: 134, data: 86, ec: 48, blocks: 2 },
  { ver: 6, total: 172, data: 108, ec: 64, blocks: 4 },
  { ver: 7, total: 196, data: 124, ec: 72, blocks: 4 },
  { ver: 8, total: 242, data: 154, ec: 88, blocks: 4 },
  { ver: 9, total: 292, data: 192, ec: 100, blocks: 5 },
  { ver: 10, total: 346, data: 230, ec: 116, blocks: 5 },
];

type Matrix = number[][];

const ALIGN_POS: Record<number, number[]> = {
  1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
  6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
};

function byteModeCapacity(ver: number, dataCodewords: number): number {
  const totalBits = dataCodewords * 8;
  const countBits = ver < 10 ? 8 : 16;
  const overheadBits = 4 + countBits + 4;
  return Math.floor((totalBits - overheadBits) / 8);
}

function byteModeEncode(data: string, version: number): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < data.length; i++) {
    const code = data.charCodeAt(i);
    if (code < 128) {
      bytes.push(code);
    } else if (code < 2048) {
      bytes.push(192 | (code >> 6), 128 | (code & 63));
    } else {
      bytes.push(224 | (code >> 12), 128 | ((code >> 6) & 63), 128 | (code & 63));
    }
  }
  const vi = VERSION_TABLE.find((v) => v.ver === version)!;
  const charCount = bytes.length;
  let modeBits: number[];
  if (version < 10) {
    modeBits = [0, 1, 0, 0];
    const lenBits = charCount.toString(2).padStart(8, '0').split('').map(Number);
    modeBits.push(...lenBits);
  } else {
    modeBits = [0, 1, 0, 0];
    const lenBits = charCount.toString(2).padStart(16, '0').split('').map(Number);
    modeBits.push(...lenBits);
  }
  const bitArr = [...modeBits];
  for (const b of bytes) {
    const bs = b.toString(2).padStart(8, '0');
    for (const ch of bs) bitArr.push(Number(ch));
  }
  const dataBits = vi.data * 8;
  while (bitArr.length < dataBits) {
    bitArr.push(0);
    if (bitArr.length < dataBits) bitArr.push(1);
  }
  bitArr.length = dataBits;
  const result: number[] = [];
  for (let i = 0; i < bitArr.length; i += 8) {
    let val = 0;
    for (let j = 0; j < 8; j++) {
      val = (val << 1) | (bitArr[i + j] || 0);
    }
    result.push(val);
  }
  return result;
}

function makeMatrix(version: number): Matrix {
  const size = 17 + version * 4;
  const m: Matrix = Array.from({ length: size }, () => new Array(size).fill(-1));
  const set = (r: number, c: number, v: number) => { if (r >= 0 && r < size && c >= 0 && c < size) m[r][c] = v; };
  const isSet = (r: number, c: number) => r >= 0 && r < size && c >= 0 && c < size && m[r][c] !== -1;

  function drawFinder(r: number, c: number) {
    for (let i = -1; i <= 7; i++) {
      for (let j = -1; j <= 7; j++) {
        if (i >= 0 && i <= 6 && j >= 0 && j <= 6) {
          const v = (i === 0 || i === 6 || j === 0 || j === 6) ? 1
            : (i >= 2 && i <= 4 && j >= 2 && j <= 4) ? 0 : 1;
          set(r + i, c + j, v);
        } else {
          set(r + i, c + j, 0);
        }
      }
    }
  }

  function drawAlignment(r: number, c: number) {
    for (let i = -2; i <= 2; i++) {
      for (let j = -2; j <= 2; j++) {
        if (i === -2 || i === 2 || j === -2 || j === 2 || (i >= -1 && i <= 1 && j >= -1 && j <= 1)) {
          const v = (i === -2 || i === 2 || j === -2 || j === 2) ? 1 : 0;
          if (!isSet(r + i, c + j)) set(r + i, c + j, v);
        }
      }
    }
  }

  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  for (let i = 8; i < size - 8; i++) {
    set(6, i, i % 2 === 0 ? 1 : 0);
    set(i, 6, i % 2 === 0 ? 1 : 0);
  }

  const aligns = ALIGN_POS[version] || [];
  for (const ar of aligns) {
    for (const ac of aligns) {
      if (ar === 6 && ac === 6) continue;
      if (ar === 6 && ac === size - 7) continue;
      if (ar === size - 7 && ac === 6) continue;
      drawAlignment(ar, ac);
    }
  }

  return m;
}

function formatBits(mask: number): number[] {
  const ecBits = 0b00;
  const data = (ecBits << 3) | mask;
  let poly = data << 10;
  const gen = 0b10100110111;
  for (let i = 14; i >= 10; i--) {
    if ((poly >> i) & 1) poly ^= gen << (i - 10);
  }
  const codeword = (data << 10) | poly;
  const result = codeword ^ 0b101010000010010;
  return result.toString(2).padStart(15, '0').split('').map(Number);
}

function applyFormat(m: Matrix, mask: number): void {
  const fmt = formatBits(mask);
  const size = m.length;
  const set = (r: number, c: number, v: number) => {
    if (r >= 0 && r < size && c >= 0 && c < size && m[r][c] === -1) m[r][c] = v;
  };
  for (let i = 0; i < 6; i++) set(8, i, fmt[i]);
  set(8, 7, fmt[6]);
  set(8, 8, fmt[7]);
  for (let i = 8; i < 15; i++) set(8, size - 16 + i, fmt[i]);
  for (let i = 0; i < 6; i++) set(i, 8, fmt[i]);
  set(7, 8, fmt[6]);
  set(8, 8, fmt[7]);
  for (let i = 8; i < 15; i++) set(size - 15 + i, 8, fmt[i]);
  set(size - 8, 8, 1);
}

const MASKS: ((r: number, c: number) => boolean)[] = [
  (r, c) => (r + c) % 2 === 0,
  (r, c) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0,
  (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0,
];

function scoreMatrix(m: Matrix): number {
  const size = m.length;
  let score = 0;
  for (let r = 0; r < size; r++) {
    let run = 1;
    for (let c = 1; c < size; c++) {
      if (m[r][c] === m[r][c - 1]) { run++; } else {
        if (run >= 5) score += run + (run >= 5 ? 3 : 0);
        run = 1;
      }
    }
    if (run >= 5) score += run + 3;
  }
  for (let c = 0; c < size; c++) {
    let run = 1;
    for (let r = 1; r < size; r++) {
      if (m[r][c] === m[r - 1][c]) { run++; } else {
        if (run >= 5) score += run + 3;
        run = 1;
      }
    }
    if (run >= 5) score += run + 3;
  }
  let dark = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (m[r][c] === 1) dark++;
    }
  }
  const pct = (dark / (size * size)) * 100;
  score += Math.abs(Math.round(pct / 5) * 5 - 50) * 10;
  return score;
}

function placeData(m: Matrix, data: number[], ec: number[]): Matrix {
  const size = m.length;
  const bits: number[] = [];
  for (const b of data) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  for (const b of ec) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }

  const result = m.map((row) => [...row]);
  let bitIdx = 0;

  for (let pair = 0; ; pair++) {
    const rightCol = size - 1 - pair;
    if (rightCol < 1) break;
    if (rightCol === 6) continue;
    const col = rightCol;
    const upward = pair % 2 === 0;

    if (upward) {
      for (let row = size - 1; row >= 0; row--) {
        for (const c of [col, col - 1]) {
          if (c < 0) continue;
          if (result[row][c] === -1 && bitIdx < bits.length) {
            result[row][c] = bits[bitIdx++];
          }
        }
      }
    } else {
      for (let row = 0; row < size; row++) {
        for (const c of [col, col - 1]) {
          if (c < 0) continue;
          if (result[row][c] === -1 && bitIdx < bits.length) {
            result[row][c] = bits[bitIdx++];
          }
        }
      }
    }
  }

  return result;
}

export function generateQRCode(text: string): number[][] {
  for (const v of VERSION_TABLE) {
    if (text.length <= byteModeCapacity(v.ver, v.data)) {
      const dataCodewords = byteModeEncode(text, v.ver);
      const dataPerBlock = v.data / v.blocks;
      const ecPerBlock = v.ec / v.blocks;
      const blocks: number[][] = [];
      for (let b = 0; b < v.blocks; b++) {
        const start = b * dataPerBlock;
        const block = dataCodewords.slice(start, start + dataPerBlock);
        const ec = rsEncode(block, ecPerBlock);
        blocks.push([...block, ...ec]);
      }
      const interleaved: number[] = [];
      for (let i = 0; i < dataPerBlock + ecPerBlock; i++) {
        for (let b = 0; b < v.blocks; b++) {
          if (i < blocks[b].length) interleaved.push(blocks[b][i]);
        }
      }
      const dataLen = dataPerBlock * v.blocks;
      const dataPart = interleaved.slice(0, dataLen);
      const ecPart = interleaved.slice(dataLen);

      let bestMatrix: Matrix | null = null;
      let bestScore = Infinity;

      for (let mask = 0; mask < 8; mask++) {
        const m = makeMatrix(v.ver);
        applyFormat(m, mask);
        const placed = placeData(m, dataPart, ecPart);
        for (let r = 0; r < placed.length; r++) {
          for (let c = 0; c < placed.length; c++) {
            if (placed[r][c] !== -1 && (r < 9 && c < 9) || (r < 9 && c >= placed.length - 8) || (r >= placed.length - 8 && c < 9)) continue;
            if (placed[r][c] !== -1 && (r === 6 || c === 6)) continue;
            if (placed[r][c] === -1) placed[r][c] = 0;
          }
        }
        for (let r = 0; r < placed.length; r++) {
          for (let c = 0; c < placed.length; c++) {
            if (r < 9 && c < 9) continue;
            if (r < 9 && c >= placed.length - 8) continue;
            if (r >= placed.length - 8 && c < 9) continue;
            if (r === 6 || c === 6) continue;
            if (MASKS[mask](r, c)) {
              placed[r][c] = placed[r][c] === 1 ? 0 : 1;
            }
          }
        }
        const sc = scoreMatrix(placed);
        if (sc < bestScore) {
          bestScore = sc;
          bestMatrix = placed;
        }
      }

      return bestMatrix!;
    }
  }
  return [];
}

export function drawQRToCanvas(
  text: string,
  canvas: HTMLCanvasElement,
  cellSize = 5,
  margin = 16
): void {
  const matrix = generateQRCode(text);
  if (matrix.length === 0) return;

  const size = matrix.length;
  canvas.width = size * cellSize + margin * 2;
  canvas.height = size * cellSize + margin * 2;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = '#0f172a';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c] === 1) {
        ctx.fillRect(margin + c * cellSize, margin + r * cellSize, cellSize, cellSize);
      }
    }
  }
}

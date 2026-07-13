const CP1252_BYTES = new Map<string, number>([
  ['€', 0x80],
  ['‚', 0x82],
  ['ƒ', 0x83],
  ['„', 0x84],
  ['…', 0x85],
  ['†', 0x86],
  ['‡', 0x87],
  ['ˆ', 0x88],
  ['‰', 0x89],
  ['Š', 0x8a],
  ['‹', 0x8b],
  ['Œ', 0x8c],
  ['Ž', 0x8e],
  ['‘', 0x91],
  ['’', 0x92],
  ['“', 0x93],
  ['”', 0x94],
  ['•', 0x95],
  ['–', 0x96],
  ['—', 0x97],
  ['˜', 0x98],
  ['™', 0x99],
  ['š', 0x9a],
  ['›', 0x9b],
  ['œ', 0x9c],
  ['ž', 0x9e],
  ['Ÿ', 0x9f],
])

function countMatches(text: string, pattern: RegExp) {
  return text.match(pattern)?.length ?? 0
}

function textScore(text: string) {
  const cjkCount = countMatches(text, /[\u3400-\u9fff\uf900-\ufaff]/g)
  const replacementCount = countMatches(text, /\uFFFD/g)
  const mojibakeMarkers = countMatches(text, /(?:Ã.|Â.|â.|[\u00a0-\u00ff]{2,}|[\u0590-\u05ff])/g)
  const controlCount = countMatches(text, /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g)

  return cjkCount * 3 - replacementCount * 12 - mojibakeMarkers * 4 - controlCount * 8
}

function looksLikeMojibake(text: string) {
  if (!text)
    return false

  if (/\uFFFD|[ÃÂâ][\u0080-\uffff]|[\u0590-\u05ff]/.test(text))
    return true

  const cjkCount = countMatches(text, /[\u3400-\u9fff\uf900-\ufaff]/g)
  const highLatinCount = countMatches(text, /[\u00a0-\u00ff]/g)
  return highLatinCount >= 3 && highLatinCount > cjkCount
}

function toSingleByteArray(text: string) {
  const bytes: number[] = []

  for (const char of text) {
    const codePoint = char.codePointAt(0)
    if (codePoint === undefined)
      return null

    if (codePoint <= 0xff) {
      bytes.push(codePoint)
      continue
    }

    const mappedByte = CP1252_BYTES.get(char)
    if (mappedByte === undefined)
      return null

    bytes.push(mappedByte)
  }

  return new Uint8Array(bytes)
}

function decodeAs(text: string, encoding: string) {
  const bytes = toSingleByteArray(text)
  if (!bytes)
    return null

  try {
    return new TextDecoder(encoding, { fatal: true }).decode(bytes)
  }
  catch {
    return null
  }
}

export function normalizeDisplayText(value: unknown) {
  if (typeof value !== 'string' || !looksLikeMojibake(value))
    return value

  const originalScore = textScore(value)
  const candidates = [
    decodeAs(value, 'utf-8'),
    decodeAs(value, 'gb18030'),
  ].filter((candidate): candidate is string => !!candidate)

  let best = value
  let bestScore = originalScore

  candidates.forEach((candidate) => {
    const score = textScore(candidate)
    if (score > bestScore + 3) {
      best = candidate
      bestScore = score
    }
  })

  return best
}

export function normalizeTextFields<T extends Record<string, any>>(record: T, fields: readonly string[]): T {
  let normalized: Record<string, any> | null = null

  fields.forEach((field) => {
    const value = record[field]
    const nextValue = normalizeDisplayText(value)
    if (nextValue !== value) {
      normalized = normalized ?? { ...record }
      normalized[field] = nextValue
    }
  })

  return (normalized as T | null) ?? record
}

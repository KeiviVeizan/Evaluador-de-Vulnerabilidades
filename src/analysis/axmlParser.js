// Android Binary XML (AXML) parser
// Handles the binary format of AndroidManifest.xml inside APK files

const CHUNK_STRING_POOL    = 0x0001
const CHUNK_START_ELEMENT  = 0x0102
const CHUNK_END_ELEMENT    = 0x0103
const UTF8_FLAG            = 1 << 8

const VAL_STRING           = 0x03
const VAL_INT_BOOLEAN      = 0x12
const VAL_INT_DEC          = 0x10
const VAL_INT_HEX          = 0x11

function u16(v, o) { return v.getUint16(o, true) }
function u32(v, o) { return v.getUint32(o, true) }
function i32(v, o) { return v.getInt32(o, true) }

function parseStringPool(view, base) {
  const headerSize  = u16(view, base + 2)
  const stringCount = u32(view, base + 8)
  const flags       = u32(view, base + 16)
  const stringsStart = u32(view, base + 20)
  const isUTF8      = Boolean(flags & UTF8_FLAG)

  const dataBase = base + stringsStart
  const strings  = []

  for (let i = 0; i < stringCount; i++) {
    const offset = u32(view, base + headerSize + i * 4)
    try {
      strings.push(isUTF8
        ? readUtf8Str(view, dataBase + offset)
        : readUtf16Str(view, dataBase + offset))
    } catch { strings.push('') }
  }
  return strings
}

function readUtf8Str(view, off) {
  let v = view.getUint8(off++)
  if (v & 0x80) { v = ((v & 0x7f) << 8) | view.getUint8(off++) }
  let byteLen = view.getUint8(off++)
  if (byteLen & 0x80) { byteLen = ((byteLen & 0x7f) << 8) | view.getUint8(off++) }
  const bytes = new Uint8Array(view.buffer, view.byteOffset + off, byteLen)
  return new TextDecoder('utf-8').decode(bytes)
}

function readUtf16Str(view, off) {
  let len = u16(view, off); off += 2
  if (len & 0x8000) { len = ((len & 0x7fff) << 16) | u16(view, off); off += 2 }
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(u16(view, off + i * 2))
  return s
}

function attrValue(view, attrBase, strings) {
  const dataType = view.getUint8(attrBase + 15)
  const data     = u32(view, attrBase + 16)
  switch (dataType) {
    case VAL_STRING:      return data < strings.length ? strings[data] : ''
    case VAL_INT_BOOLEAN: return data !== 0
    case VAL_INT_DEC:     return data
    case VAL_INT_HEX:     return '0x' + data.toString(16)
    default:              return data
  }
}

export function parseAXML(uint8Array) {
  // Build a clean ArrayBuffer copy for DataView
  const ab   = uint8Array.buffer.slice(uint8Array.byteOffset, uint8Array.byteOffset + uint8Array.byteLength)
  const view = new DataView(ab)

  if (u16(view, 0) !== 0x0003) throw new Error('Not valid AXML')

  const fileSize = u32(view, 4)
  let strings = []
  let off = 8
  const root = { name: '#doc', attributes: {}, children: [] }
  const stack = [root]

  while (off + 8 <= Math.min(fileSize, view.byteLength)) {
    const chunkType = u16(view, off)
    const chunkSize = u32(view, off + 4)
    if (chunkSize < 8 || off + chunkSize > view.byteLength) break

    if (chunkType === CHUNK_STRING_POOL) {
      strings = parseStringPool(view, off)
    } else if (chunkType === CHUNK_START_ELEMENT) {
      const nsIdx    = i32(view, off + 16)
      const nameIdx  = i32(view, off + 20)
      const attrStart = u16(view, off + 24) // relative to attrExt (off+16)
      const attrSize  = u16(view, off + 26) // usually 20
      const attrCount = u16(view, off + 28)

      const elem = {
        name:       nameIdx >= 0 ? strings[nameIdx] : '',
        ns:         nsIdx   >= 0 ? strings[nsIdx]   : '',
        attributes: {},
        children:   [],
      }

      for (let i = 0; i < attrCount; i++) {
        const aOff = off + 16 + attrStart + i * (attrSize || 20)
        if (aOff + 20 > view.byteLength) break
        const nameI = i32(view, aOff + 4)
        const name  = nameI >= 0 ? strings[nameI] : ''
        if (name) elem.attributes[name] = attrValue(view, aOff, strings)
      }

      stack[stack.length - 1].children.push(elem)
      stack.push(elem)
    } else if (chunkType === CHUNK_END_ELEMENT) {
      if (stack.length > 1) stack.pop()
    }

    off += chunkSize
  }

  return root.children[0] || null
}

export function extractManifestInfo(tree) {
  if (!tree) return null
  const info = {
    packageName: tree.attributes.package ?? null,
    versionName: tree.attributes.versionName ?? null,
    permissions: [],
    debuggable: null,
    allowBackup: null,
    usesCleartextTraffic: null,
    hasNetworkSecurityConfig: false,
    targetSdk: null,
    minSdk: null,
  }

  for (const child of tree.children ?? []) {
    switch (child.name) {
      case 'uses-permission': {
        const n = child.attributes.name
        if (n) info.permissions.push(n)
        break
      }
      case 'uses-sdk': {
        info.targetSdk = child.attributes.targetSdkVersion ?? null
        info.minSdk    = child.attributes.minSdkVersion    ?? null
        break
      }
      case 'application': {
        info.debuggable               = child.attributes.debuggable              ?? null
        info.allowBackup              = child.attributes.allowBackup             ?? null
        info.usesCleartextTraffic     = child.attributes.usesCleartextTraffic    ?? null
        info.hasNetworkSecurityConfig = 'networkSecurityConfig' in child.attributes
        break
      }
    }
  }
  return info
}

// A Merkle-Patricia trie built from all its entries, for proofs no RPC serves (receipt tries).
// Node shapes and hashing as Ethereum's; a node under 32 bytes is embedded in its parent.
import { keccak256, encodeRlp, getBytes, hexlify } from 'ethers'

const nibbles = b => [...getBytes(b)].flatMap(x => [x >> 4, x & 15])

function hexPrefix(nib, leaf) {
  const odd = nib.length % 2, flag = (leaf ? 2 : 0) + odd
  const out = [odd ? flag * 16 + nib[0] : flag * 16]
  for (let i = odd; i < nib.length; i += 2) out.push(nib[i] * 16 + nib[i + 1])
  return hexlify(Uint8Array.from(out))
}

const made = (struct, meta) => ({ struct, enc: encodeRlp(struct), ...meta })
const embedded = n => getBytes(n.enc).length < 32
const ref = n => (embedded(n) ? n.struct : keccak256(n.enc))

function build(entries) {
  if (entries.length === 1) return made([hexPrefix(entries[0].k, true), entries[0].v], { leaf: true })
  let pre = 0
  while (entries.every(e => e.k.length > pre && e.k[pre] === entries[0].k[pre])) pre++
  if (pre > 0) {
    const child = build(entries.map(e => ({ k: e.k.slice(pre), v: e.v })))
    return made([hexPrefix(entries[0].k.slice(0, pre), false), ref(child)], { skip: pre, child })
  }
  const kids = Array.from({ length: 16 }, (_, i) => {
    const group = entries.filter(e => e.k.length > 0 && e.k[0] === i)
    return group.length ? build(group.map(e => ({ k: e.k.slice(1), v: e.v }))) : null
  })
  const value = entries.find(e => e.k.length === 0)?.v ?? '0x'
  return made([...kids.map(c => (c ? ref(c) : '0x')), value], { kids })
}

/// a trie of [key, value] pairs (hex): its root and proofs (the nodes reached by hash, root first)
export function trie(pairs) {
  if (pairs.length === 0) return { root: keccak256('0x80'), proof: () => ['0x80'] }
  const root = build(pairs.map(([k, v]) => ({ k: nibbles(k), v: hexlify(v) })))
  return {
    root: keccak256(root.enc),
    proof(key) {
      const out = [root.enc]
      let n = root, k = nibbles(key)
      for (;;) {
        if (n.leaf) break
        if (n.child) { k = k.slice(n.skip); n = n.child } else { if (k.length === 0 || !n.kids[k[0]]) break; n = n.kids[k[0]]; k = k.slice(1) }
        if (!embedded(n)) out.push(n.enc)
      }
      return out
    },
  }
}

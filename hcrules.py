"""A pure-Python implementation of the hashcat / John the Ripper rule language.

Only *applies* rules to candidate base words (forward direction), exactly like
hashcat does on the GPU. Reference: https://hashcat.net/wiki/doku.php?id=rule_based_attack
"""

POS = {c: i for i, c in enumerate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")}

# Argument spec per opcode: N = position (0-9A-Z), X = literal character
ARGS = {
    ':': '', 'l': '', 'u': '', 'c': '', 'C': '', 't': '', 'T': 'N', 'r': '', 'd': '',
    'p': 'N', 'f': '', '{': '', '}': '', '$': 'X', '^': 'X', '[': '', ']': '',
    'D': 'N', 'x': 'NN', 'O': 'NN', 'i': 'NX', 'o': 'NX', "'": 'N', 's': 'XX',
    '@': 'X', 'z': 'N', 'Z': 'N', 'q': '', 'k': '', 'K': '', '*': 'NN', 'L': 'N',
    'R': 'N', '+': 'N', '-': 'N', '.': 'N', ',': 'N', 'y': 'N', 'Y': 'N', 'E': '',
    'e': 'X', '3': 'NX',
    # rejection rules
    '<': 'N', '>': 'N', '_': 'N', '!': 'X', '/': 'X', '(': 'X', ')': 'X',
    '=': 'NX', '%': 'NX', 'Q': '',
    # memory rules
    'M': '', '4': '', '6': '', 'X': 'NNN',
}

# Ops whose effect on length does not depend on the word (assuming non-empty word).
_ZERO = set(":lucCtTrso*kKLR+-.,Ee3<>_!/()=%QM")
_PLUS1 = set("$^")
_MINUS1 = set("[]")


class RuleError(ValueError):
    pass


def parse_rule(text):
    ops = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in ' \t':
            i += 1
            continue
        spec = ARGS.get(ch)
        if spec is None:
            raise RuleError(f"unsupported op {ch!r}")
        raw = text[i + 1:i + 1 + len(spec)]
        if len(raw) < len(spec):
            raise RuleError("truncated rule")
        args = []
        for kind, a in zip(spec, raw):
            if kind == 'N':
                if a not in POS:
                    raise RuleError(f"bad position {a!r}")
                args.append(POS[a])
            else:
                args.append(a)
        ops.append((ch, *args))
        i += 1 + len(spec)
    return tuple(ops)


def length_delta(ops):
    """Fixed length change of a rule, or None if it depends on the word."""
    d = 0
    for op in ops:
        o = op[0]
        if o in _ZERO:
            continue
        if o in _PLUS1:
            d += 1
        elif o in _MINUS1:
            d -= 1
        elif o in 'zZ':
            d += op[1]
        else:
            return None
    return d


def growth_bound(ops):
    """(mult, add) such that len(result) <= mult * len(word) + add."""
    mult, add = 1, 0
    for op in ops:
        o = op[0]
        if o in "$^i":
            add += 1
        elif o in "dfq":
            mult, add = mult * 2, add * 2
        elif o == 'p':
            mult, add = mult * (op[1] + 1), add * (op[1] + 1)
        elif o in "zZyY":
            add += op[1]
        elif o == 'X':
            add += op[2]
        elif o in "46":
            mult, add = mult * 2, add * 2
    return mult, add


def _toggle(ch):
    return ch.lower() if ch.isupper() else ch.upper()


def apply_rule(ops, w):
    """Apply parsed rule to word w. Returns new word, or None if rejected."""
    mem = w
    for op in ops:
        o = op[0]
        n = len(w)
        if o == '$':
            w = w + op[1]
        elif o == '^':
            w = op[1] + w
        elif o == ':':
            pass
        elif o == 'i':
            p = op[1]
            if p <= n:
                w = w[:p] + op[2] + w[p:]
        elif o == 'o':
            p = op[1]
            if p < n:
                w = w[:p] + op[2] + w[p + 1:]
        elif o == 's':
            w = w.replace(op[1], op[2])
        elif o == 'l':
            w = w.lower()
        elif o == 'u':
            w = w.upper()
        elif o == 'c':
            w = w[:1].upper() + w[1:].lower()
        elif o == 'C':
            w = w[:1].lower() + w[1:].upper()
        elif o == 't':
            w = w.swapcase()
        elif o == 'T':
            p = op[1]
            if p < n:
                w = w[:p] + _toggle(w[p]) + w[p + 1:]
        elif o == 'r':
            w = w[::-1]
        elif o == 'd':
            w = w + w
        elif o == 'p':
            w = w * (op[1] + 1)
        elif o == 'f':
            w = w + w[::-1]
        elif o == '{':
            w = w[1:] + w[:1]
        elif o == '}':
            w = w[-1:] + w[:-1]
        elif o == '[':
            w = w[1:]
        elif o == ']':
            w = w[:-1]
        elif o == 'D':
            p = op[1]
            if p < n:
                w = w[:p] + w[p + 1:]
        elif o == 'x':
            p, m = op[1], op[2]
            if p < n and p + m <= n:
                w = w[p:p + m]
        elif o == 'O':
            p, m = op[1], op[2]
            if p < n and p + m <= n:
                w = w[:p] + w[p + m:]
        elif o == "'":
            if op[1] < n:
                w = w[:op[1]]
        elif o == '@':
            w = w.replace(op[1], '')
        elif o == 'z':
            if n:
                w = w[0] * op[1] + w
        elif o == 'Z':
            if n:
                w = w + w[-1] * op[1]
        elif o == 'q':
            w = ''.join(c + c for c in w)
        elif o == 'k':
            if n >= 2:
                w = w[1] + w[0] + w[2:]
        elif o == 'K':
            if n >= 2:
                w = w[:-2] + w[-1] + w[-2]
        elif o == '*':
            a, b = op[1], op[2]
            if a < n and b < n:
                lst = list(w)
                lst[a], lst[b] = lst[b], lst[a]
                w = ''.join(lst)
        elif o in 'LR+-':
            p = op[1]
            if p < n:
                c = ord(w[p])
                c = {'L': (c << 1) & 0xFF, 'R': c >> 1, '+': (c + 1) & 0xFF, '-': (c - 1) & 0xFF}[o]
                w = w[:p] + chr(c) + w[p + 1:]
        elif o == '.':
            p = op[1]
            if p + 1 < n:
                w = w[:p] + w[p + 1] + w[p + 1:]
        elif o == ',':
            p = op[1]
            if 1 <= p < n:
                w = w[:p] + w[p - 1] + w[p + 1:]
        elif o == 'y':
            if op[1] <= n:
                w = w[:op[1]] + w
        elif o == 'Y':
            if op[1] <= n:
                w = w + w[n - op[1]:]
        elif o == 'E':
            w = _title(w.lower(), ' ')
        elif o == 'e':
            w = _title(w.lower(), op[1])
        elif o == '3':
            p, x = op[1], op[2]
            cnt = -1
            for idx, ch in enumerate(w):
                if ch == x:
                    cnt += 1
                    if cnt == p:
                        if idx + 1 < n:
                            w = w[:idx + 1] + _toggle(w[idx + 1]) + w[idx + 2:]
                        break
        elif o == 'M':
            mem = w
        elif o == '4':
            w = w + mem
        elif o == '6':
            w = mem + w
        elif o == 'X':
            a, m, p = op[1], op[2], op[3]
            if a + m <= len(mem) and p <= n:
                w = w[:p] + mem[a:a + m] + w[p:]
        # rejections
        elif o == '<':
            if n > op[1]:
                return None
        elif o == '>':
            if n < op[1]:
                return None
        elif o == '_':
            if n != op[1]:
                return None
        elif o == '!':
            if op[1] in w:
                return None
        elif o == '/':
            if op[1] not in w:
                return None
        elif o == '(':
            if not w.startswith(op[1]):
                return None
        elif o == ')':
            if not w.endswith(op[1]):
                return None
        elif o == '=':
            if not (op[1] < n and w[op[1]] == op[2]):
                return None
        elif o == '%':
            if w.count(op[2]) < op[1]:
                return None
        elif o == 'Q':
            if w == mem:
                return None
    return w


def _title(w, sep):
    out, up = [], True
    for ch in w:
        out.append(ch.upper() if up else ch)
        up = ch == sep
    return ''.join(out)


class RuleSet:
    """A hashcat rule file. Keeps every line (hashcat counts them all) and
    indexes rules by fixed length-delta so matching is fast."""

    def __init__(self, name, texts, ops_list):
        self.name = name
        self.texts = texts          # original rule text per index
        self.ops = ops_list         # parsed ops or None (unsupported)
        self.size = len(texts)
        self._by_delta = {}
        self._variable = {}         # growth bound -> rule indices
        for idx, ops in enumerate(ops_list):
            if ops is None:
                continue
            d = length_delta(ops)
            if d is None:
                self._variable.setdefault(growth_bound(ops), []).append(idx)
            else:
                self._by_delta.setdefault(d, []).append(idx)
        self._merged = {}

    @classmethod
    def from_file(cls, path, name=None):
        import os
        texts, ops_list = [], []
        with open(path, encoding='latin-1') as f:
            for line in f:
                line = line.rstrip('\r\n')
                if not line or line.startswith('#'):
                    continue
                try:
                    ops = parse_rule(line)
                except RuleError:
                    ops = None
                texts.append(line)
                ops_list.append(ops)
        return cls(name or os.path.splitext(os.path.basename(path))[0], texts, ops_list)

    @classmethod
    def stacked(cls, a, b):
        """hashcat -r a -r b : every combination, applied a then b."""
        texts, ops_list = [], []
        for ta, oa in zip(a.texts, a.ops):
            for tb, ob in zip(b.texts, b.ops):
                texts.append(f"{ta}  then  {tb}")
                ops_list.append(None if oa is None or ob is None else oa + ob)
        return cls(f"{a.name} x {b.name}", texts, ops_list)

    def unsupported(self):
        return sum(1 for o in self.ops if o is None)

    def first_match(self, word, target):
        """Smallest rule index that turns `word` into `target`, or None."""
        lw, lt = len(word), len(target)
        idxs = self._merged.get((lw, lt))
        if idxs is None:
            idxs = list(self._by_delta.get(lt - lw, []))
            for (mult, add), lst in self._variable.items():
                if mult * lw + add >= lt:
                    idxs += lst
            idxs.sort()
            self._merged[(lw, lt)] = idxs
        ops = self.ops
        for idx in idxs:
            if apply_rule(ops[idx], word) == target:
                return idx
        return None

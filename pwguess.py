#!/usr/bin/env python3
"""pwguess - estimate how many guesses real cracking tools would need for a password.

Fully offline: an audit hook blocks all network access and process launches at
startup, the password is read without echo, never written anywhere, and not
printed (not even in pieces) unless --show is given. No hash is ever computed or
cracked. The program only asks "at what position would attack X produce this
exact string?"

Attacks modelled (each estimated independently; the minimum wins, which is the
"min_auto" methodology of Ur et al., USENIX Security 2015):

  brute     hashcat -a 3 ?a?a?a... with --increment
  mask      hashcat -a 3 with masks from PACK statsgen/maskgen, ordered by optindex
  dict      hashcat -a 0 wordlist                      (straight dictionary)
  rules     hashcat -a 0 wordlist -r best66/dive/...   (real hashcat rule files)
  hybrid    hashcat -a 6 / -a 7 wordlist + mask
  prince    hashcat -a 1 / princeprocessor word chains (probability-ordered)
  kwalk     kwprocessor keyboard walks
  pcfg      Weir's PCFG cracker (pcfg_cracker), trained on the password list
  markov    3-gram Markov (JtR --incremental / OMEN style), trained on the list

PCFG and Markov guess numbers use the Monte Carlo estimator of Dell'Amico &
Filippone (CCS 2015), which gives the rank of a password in a probability-ordered
enumeration without enumerating it.
"""

# ---------------------------------------------------------------------------
# Offline guard: nothing below may touch the network or start another program.
# A runtime audit hook (PEP 578) is raised from inside the interpreter's C code,
# so it catches every socket created, every DNS lookup (getaddrinfo,
# gethostbyname, ...) and every process launch, including calls made through the
# raw `_socket` module. Once added, an audit hook cannot be removed. This guards
# against mistakes in this program and its imports; it is not a sandbox against
# hostile code running in the same process.
import sys as _sys

_BLOCKED_EVENTS = ("socket.", "subprocess.Popen", "os.system", "os.exec", "os.spawn",
                   "os.posix_spawn", "os.startfile", "webbrowser.open")


def _offline_guard(event, _args):
    if event.startswith(_BLOCKED_EVENTS):
        raise RuntimeError(f"pwguess: blocked {event} - this program never uses the "
                           f"network or starts other programs")


_sys.addaudithook(_offline_guard)
# ---------------------------------------------------------------------------

import argparse
import bisect
import getpass
import math
import os
import pickle
import random
import re
import string
import sys
import time
import unicodedata
from collections import Counter
from itertools import accumulate

from hcrules import RuleSet

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
RULES = os.path.join(HERE, "rules")
PW_FILE = os.path.join(DATA, "passwords.txt")
WORD_FILES = {"en": os.path.join(DATA, "en_words.txt"),
              "cs": os.path.join(DATA, "cs_words.txt")}
LANGS = {"en": (["en"], "English", "en_words.txt"),
         "cs": (["cs"], "Czech", "cs_words.txt"),
         "mixed": (["en", "cs"], "English+Czech", "en+cs_words.txt")}
CACHE_VERSION = 5


def cache_path(lang):
    return os.path.join(DATA, f"model_cache_{lang}.pkl")


def fold_diacritics(w):
    """'žluťoučký' -> 'zlutoucky' (how most people type Czech in passwords)."""
    return "".join(c for c in unicodedata.normalize("NFKD", w) if not unicodedata.combining(c))


def load_wordlist(lang):
    """Ranked word list as an attacker would build it: each word followed by its
    diacritics-free form; for mixed mode the languages are interleaved by rank."""
    files, label, fname = LANGS[lang]
    per_lang = []
    for code in files:
        words = []
        for line in read_lines(WORD_FILES[code]):
            words.append(line.split()[0].lower())
        per_lang.append((code, words))
    rank, orig, origin = {}, {}, {}
    longest = max(len(ws) for _, ws in per_lang)
    for i in range(longest):
        for code, ws in per_lang:
            if i >= len(ws):
                continue
            w = ws[i]
            f = fold_diacritics(w)
            for v in ((f, w) if f != w else (w,)):
                if v not in rank:
                    rank[v] = len(rank) + 1
                    origin[v] = code
                    if v != w:
                        orig[v] = w
    return rank, orig, origin, label, fname

RULE_FILES = ["best66", "leetspeak", "rockyou-30000", "dive"]
MC_SAMPLES = 100_000

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SPECIALS = string.punctuation + " "          # hashcat ?s = 33 chars
PRINTABLE = "".join(chr(i) for i in range(32, 127))  # hashcat ?a = 95 chars
CLASS_SIZE = {"l": 26, "u": 26, "d": 10, "s": 33, "b": 256}

_MASK_TT = str.maketrans({**{c: "l" for c in LOWER}, **{c: "u" for c in UPPER},
                          **{c: "d" for c in DIGITS}, **{c: "s" for c in SPECIALS}})
_NONMASK = re.compile(r"[^luds]")


def mask_of(pw):
    """Compact hashcat mask, e.g. 'Summer1!' -> 'ulllllds' (= ?u?l?l?l?l?l?d?s)."""
    return _NONMASK.sub("b", pw.translate(_MASK_TT))


def mask_keyspace(m):
    k = 1
    for c in m:
        k *= CLASS_SIZE[c]
    return k


def hc_mask(m):
    return "".join("?" + c for c in m)


# ===========================================================================
# Model training (done once, cached in data/model_cache.pkl)
# ===========================================================================

SEG_RE = re.compile(r"[A-Za-z]+|[0-9]+|[^A-Za-z0-9]+")
_CAPS_TT = str.maketrans({**{c: "L" for c in LOWER}, **{c: "U" for c in UPPER}})
ASCII_LETTERS = set(string.ascii_letters)


def seg_class(s):
    c = s[0]
    if c in ASCII_LETTERS:
        return "A"
    if "0" <= c <= "9":
        return "D"
    return "O"


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line:
                yield line


class MonteCarlo:
    """Dell'Amico & Filippone estimator: rank(p) ~= sum_{i: p_i > p} 1/(n p_i)."""

    def __init__(self, logps):
        logps = sorted(logps, reverse=True)
        n = len(logps)
        self.neg = [-lp for lp in logps]  # ascending
        self.prefix = [0.0] + list(accumulate(math.exp(-lp) / n for lp in logps))

    def rank(self, logp):
        k = bisect.bisect_left(self.neg, -logp)   # samples strictly more probable
        return max(1.0, self.prefix[k])


class Model:
    pass


def train(log, lang):
    m = Model()
    t0 = time.time()
    pw_list = list(read_lines(PW_FILE))
    m.pw_rank = {}
    for i, p in enumerate(pw_list, 1):
        m.pw_rank.setdefault(p, i)
    m.pw_size = len(m.pw_rank)

    m.lang = lang
    m.word_rank, m.word_orig, m.word_origin, m.word_label, m.word_file = load_wordlist(lang)
    m.word_size = len(m.word_rank)
    log(f"  wordlists loaded: {m.pw_size:,} passwords, {m.word_size:,} {m.word_label} words")

    # --- PACK statsgen + maskgen ------------------------------------------
    mc = Counter(map(mask_of, pw_list))
    ordered = sorted(mc.items(), key=lambda kv: kv[1] / mask_keyspace(kv[0]), reverse=True)
    m.mask_pos = {}
    before = 0
    for i, (mk, cnt) in enumerate(ordered, 1):
        ks = mask_keyspace(mk)
        m.mask_pos[mk] = (i, before, ks, cnt)
        before += ks
    m.mask_total = len(ordered)
    log(f"  PACK masks: {m.mask_total:,} distinct")

    # --- PCFG (Weir et al. 2009; pcfg_cracker v4 style) --------------------
    structs, caps, terms = Counter(), {}, {}
    for pw in pw_list:
        segs = SEG_RE.findall(pw)
        key = []
        for s in segs:
            cls, n = seg_class(s), len(s)
            key.append(f"{cls}{n}")
            if cls == "A":
                caps.setdefault(n, Counter())[s.translate(_CAPS_TT)] += 1
                terms.setdefault(("A", n), Counter())[s.lower()] += 1
            else:
                terms.setdefault((cls, n), Counter())[s] += 1
        structs[" ".join(key)] += 1
    m.structs = structs
    m.structs_total = sum(structs.values())
    m.caps = {n: (c, sum(c.values())) for n, c in caps.items()}
    m.terms = {k: (c, sum(c.values())) for k, c in terms.items()}

    word_by_len = {}
    for w, r in m.word_rank.items():
        if w.isascii() and w.isalpha():
            word_by_len.setdefault(len(w), []).append((r, w))
    m.word_len_z = {n: sum(1.0 / r for r, _ in lst) for n, lst in word_by_len.items()}
    log(f"  PCFG: {len(structs):,} base structures")

    # --- Markov 3-gram -----------------------------------------------------
    big = "".join("\x02\x02" + p + "\x03" for p in pw_list if p.isascii() and p.isprintable())
    tri = Counter(zip(big, big[1:], big[2:]))
    ctx = {}
    for (a, b, c), n in tri.items():
        if a == "\x03" or b == "\x03":
            continue
        d = ctx.setdefault(a + b, [0, {}])
        d[0] += n
        d[1][c] = d[1].get(c, 0) + n
    m.markov = ctx
    del big, tri
    log(f"  Markov: {len(ctx):,} contexts")

    # --- Monte Carlo samples ----------------------------------------------
    rng = random.Random(1337)
    m.pcfg_mc = MonteCarlo(_sample_pcfg(m, rng, word_by_len, MC_SAMPLES))
    m.markov_mc = MonteCarlo(_sample_markov(m, rng, MC_SAMPLES))
    log(f"  Monte Carlo: {MC_SAMPLES:,} samples each  ({time.time() - t0:.1f}s total)")

    m.rules = {}
    for name in RULE_FILES:
        path = os.path.join(RULES, name + ".rule")
        if os.path.exists(path):
            m.rules[name] = RuleSet.from_file(path)
    return m


def load_model(log, lang):
    word_files = [WORD_FILES[c] for c in LANGS[lang][0]]
    stamp = [CACHE_VERSION, lang]
    for p in [PW_FILE] + word_files + [os.path.join(RULES, r + ".rule") for r in RULE_FILES]:
        stamp.append((os.path.basename(p), os.path.getsize(p) if os.path.exists(p) else -1))
    cache = cache_path(lang)
    if os.path.exists(cache):
        try:
            with open(cache, "rb") as f:
                saved_stamp, m = pickle.load(f)
            if saved_stamp == stamp:
                return m
        except Exception:
            pass
    for p in [PW_FILE] + word_files:
        if not os.path.exists(p):
            sys.exit(f"missing {os.path.relpath(p, HERE)} - run `python fetch_data.py` first")
    log(f"Training {LANGS[lang][1]} models from the wordlists (first run per language, ~30 s)...")
    m = train(log, lang)
    with open(cache, "wb") as f:
        pickle.dump((stamp, m), f, protocol=pickle.HIGHEST_PROTOCOL)
    return m


# ===========================================================================
# PCFG probability + sampling
# ===========================================================================

WORD_SHARE = 0.8  # share of the alpha back-off mass given to the word dictionary


def _wb(counter_total):
    """Witten-Bell back-off weight for a (Counter, total) pair."""
    c, n = counter_total
    t = len(c)
    return t / (n + t)


def pcfg_parse(m, pw):
    """Return (log p, explanation list) under the PCFG, or (None, reason)."""
    segs = SEG_RE.findall(pw)
    key = " ".join(f"{seg_class(s)}{len(s)}" for s in segs)
    sc = m.structs.get(key, 0)
    if not sc:
        return None, f"base structure {key} never seen in training"
    logp = math.log(sc / m.structs_total)
    parts = [f"structure {key} (p={sc / m.structs_total:.2g})"]
    for s in segs:
        cls, n = seg_class(s), len(s)
        if cls == "A":
            lw = s.lower()
            ct = m.terms.get(("A", n))
            back = (1 - WORD_SHARE) * 26.0 ** -n
            if n in m.word_len_z and lw in m.word_rank:
                back += WORD_SHARE * (1.0 / m.word_rank[lw]) / m.word_len_z[n]
            elif n not in m.word_len_z:
                back = 26.0 ** -n
            p = _mix(ct, lw, back)
            cm = s.translate(_CAPS_TT)
            cc = m.caps.get(n)
            pc = _mix(cc, cm, 2.0 ** -n)
            logp += math.log(p) + math.log(pc)
            parts.append(f"'{lw}' p={p:.2g} caps {cm} p={pc:.2g}")
        else:
            ct = m.terms.get((cls, n))
            if cls == "D":
                back = 10.0 ** -n
            else:
                back = 1.0
                for ch in s:
                    back *= (1 / 33) if ch in SPECIALS else 1e-6
            p = _mix(ct, s, back)
            logp += math.log(p)
            parts.append(f"'{s}' p={p:.2g}")
    return logp, parts


def _mix(counter_total, item, back):
    if counter_total is None:
        return back
    c, n = counter_total
    b = _wb(counter_total)
    return (1 - b) * c.get(item, 0) / n + b * back


def _sample_pcfg(m, rng, word_by_len, k):
    skeys = list(m.structs)
    scum = list(accumulate(m.structs[s] for s in skeys))
    tcache = {}

    def cum(table, key):
        if key not in tcache:
            c, _ = table[key]
            items = list(c)
            tcache[key] = (items, list(accumulate(c[i] for i in items)))
        return tcache[key]

    word_cum = {}
    for n, lst in word_by_len.items():
        lst.sort()
        word_cum[n] = ([w for _, w in lst], list(accumulate(1.0 / r for r, _ in lst)))

    out = []
    while len(out) < k:
        key = rng.choices(skeys, cum_weights=scum)[0]
        pw = []
        for tok in key.split():
            cls, n = tok[0], int(tok[1:])
            table_key = (cls, n)
            ct = m.terms[table_key]
            if rng.random() >= _wb(ct):
                items, cw = cum(m.terms, table_key)
                s = rng.choices(items, cum_weights=cw)[0]
            elif cls == "A":
                if n in word_cum and rng.random() < WORD_SHARE:
                    items, cw = word_cum[n]
                    s = rng.choices(items, cum_weights=cw)[0]
                else:
                    s = "".join(rng.choice(LOWER) for _ in range(n))
            elif cls == "D":
                s = "".join(rng.choice(DIGITS) for _ in range(n))
            else:
                s = "".join(rng.choice(SPECIALS) for _ in range(n))
            if cls == "A":
                cc = m.caps[n]
                if rng.random() >= _wb(cc):
                    items, cw = cum(m.caps, n)
                    cm = rng.choices(items, cum_weights=cw)[0]
                else:
                    cm = "".join(rng.choice("LU") for _ in range(n))
                s = "".join(ch.upper() if f == "U" else ch for ch, f in zip(s, cm))
            pw.append(s)
        lp, _ = pcfg_parse(m, "".join(pw))
        if lp is not None:
            out.append(lp)
    return out


# ===========================================================================
# Markov
# ===========================================================================

MARKOV_DELTA = 0.01
MARKOV_V = len(PRINTABLE) + 1  # + end symbol


def markov_logp(m, pw):
    s = "\x02\x02" + pw + "\x03"
    lp = 0.0
    for i in range(2, len(s)):
        c = s[i]
        d = m.markov.get(s[i - 2:i])
        if c != "\x03" and not (" " <= c <= "~"):
            lp += math.log(1e-6)      # non-ASCII: essentially never generated
            c = "?"
        if d is None:
            lp += math.log(1 / MARKOV_V)
        else:
            lp += math.log((d[1].get(c, 0) + MARKOV_DELTA) / (d[0] + MARKOV_DELTA * MARKOV_V))
    return lp


def _sample_markov(m, rng, k):
    syms = list(PRINTABLE) + ["\x03"]
    cache = {}
    uniform = list(accumulate([1.0] * MARKOV_V))
    out = []
    while len(out) < k:
        ctx, pw = "\x02\x02", []
        while len(pw) < 40:
            cw = cache.get(ctx)
            if cw is None:
                d = m.markov.get(ctx)
                cw = uniform if d is None else list(
                    accumulate(d[1].get(c, 0) + MARKOV_DELTA for c in syms))
                cache[ctx] = cw
            c = rng.choices(syms, cum_weights=cw)[0]
            if c == "\x03":
                break
            pw.append(c)
            ctx = ctx[1] + c
        else:
            continue
        out.append(markov_logp(m, "".join(pw)))
    return out


# ===========================================================================
# Attacks
# ===========================================================================

class Result:
    def __init__(self, attack, tool, guesses, detail):
        self.attack, self.tool, self.guesses, self.detail = attack, tool, guesses, detail


def attack_brute(pw):
    n = len(pw)
    tool = "hashcat -a 3 -i ?a" + "?a" * (n - 1)
    if not all(c in PRINTABLE for c in pw):
        return Result("Brute force", tool, None, "contains non-ASCII characters, which ?a never produces")
    g = sum(95 ** i for i in range(1, n)) + (95 ** n) // 2
    return Result("Brute force", tool, g, f"all 95-char strings up to length {n}")


def attack_mask(m, pw):
    mk = mask_of(pw)
    pos = m.mask_pos.get(mk)
    ks = mask_keyspace(mk)
    if pos is None:
        return Result("Mask (PACK)", "hashcat -a 3 <maskgen .hcmask>", None,
                      f"mask {hc_mask(mk)} never occurs in the training list")
    i, before, ks, cnt = pos
    return Result("Mask (PACK)", "hashcat -a 3 <maskgen .hcmask>", before + ks // 2,
                  f"{hc_mask(mk)} is mask #{i:,} of {m.mask_total:,} by optindex "
                  f"({cnt:,} training hits, keyspace {ks:.2e})")


def attack_dict(m, pw):
    out = []
    r = m.pw_rank.get(pw)
    out.append(Result("Dictionary", "hashcat -a 0 passwords.txt", r,
                      f"rank {r:,} in leaked-password list" if r else "not in leaked-password list"))
    r = m.word_rank.get(pw)
    out.append(Result("Dictionary", f"hashcat -a 0 {m.word_file}", r,
                      f"rank {r:,} in {m.word_label} word list{word_note(m, pw)}" if r
                      else f"not in {m.word_label} word list"))
    return out


def word_note(m, w):
    """Language / diacritics annotation for a word from the word list."""
    bits = []
    if m.lang == "mixed" and w in m.word_origin:
        bits.append(m.word_origin[w])
    if w in m.word_orig:
        bits.append(f"'{m.word_orig[w]}' without diacritics")
    return f" ({', '.join(bits)})" if bits else ""


LEET = {"0": "o", "1": "il", "3": "e", "4": "a", "@": "a", "$": "s", "5": "s", "7": "t",
        "!": "i", "9": "g", "6": "b", "+": "t", "<": "c", "{": "c", "%": "x", "8": "b"}


def _unleet(s, limit=64):
    """All strings obtained by reverting leet chars (each char type all-or-nothing)."""
    out = {s}
    for ch in set(s) & set(LEET):
        new = set()
        for v in out:
            for rep in LEET[ch]:
                new.add(v.replace(ch, rep))
        out |= new
        if len(out) > limit:
            break
    return out


def candidate_bases(pw):
    n = len(pw)
    cands = set()
    for i in range(n):
        for j in range(i + 2, n + 1):
            s = pw[i:j]
            lo = s.lower()
            for v in (s, lo, lo.capitalize(), s[::-1], lo[::-1]):
                cands.add(v)
            if j - i >= 3:
                for u in _unleet(lo):
                    cands.add(u)
                    cands.add(u[::-1])
    return cands


def attack_rules(m, pw, rulesets):
    cands = candidate_bases(pw)
    out = []
    for wl_name, rank in (("passwords.txt", m.pw_rank), (m.word_file, m.word_rank)):
        words = sorted((rank[w], w) for w in cands if w in rank)
        for rs in rulesets:
            res = None
            for r, w in words:
                if (r - 1) * rs.size > 1e18:
                    break
                idx = rs.first_match(w, pw)
                if idx is not None:
                    g = (r - 1) * rs.size + idx + 1
                    note = word_note(m, w) if rank is m.word_rank else ""
                    res = Result("Dict + rules", f"hashcat -a 0 {wl_name} -r {rs.name}.rule", g,
                                 f"base '{w}' (rank {r:,}{note}) x rule #{idx + 1} `{rs.texts[idx]}` "
                                 f"of {rs.size:,}")
                    break
            if res is None:
                res = Result("Dict + rules", f"hashcat -a 0 {wl_name} -r {rs.name}.rule", None,
                             "no word + rule produces it")
            out.append(res)
    return out


def _word_rank(m, w):
    """Best (rank, how) for w used as a wordlist entry, allowing -j case rules."""
    best = None
    variants = [(w, 1, "")]
    lo = w.lower()
    if lo != w and (w == lo.capitalize() or w == w.upper()):
        variants.append((lo, 2, " + case rule (-j c / -j u)"))
    for variant, factor, how in variants:
        for rank in (m.pw_rank, m.word_rank):
            r = rank.get(variant)
            if r and (best is None or r * factor < best[0]):
                if rank is m.pw_rank:
                    src = "(leaked)"
                else:
                    src = f"({m.word_origin.get(variant, m.lang)} words"
                    if variant in m.word_orig:
                        src += f", '{m.word_orig[variant]}' without diacritics"
                    src += ")"
                best = (r * factor, f"'{variant}' rank {r:,} {src}{how}")
    return best


def attack_hybrid(m, pw):
    best = None
    n = len(pw)
    for k in range(1, min(6, n - 1) + 1):
        for word, aff, mode in ((pw[:-k], pw[-k:], "-a 6 word+mask"), (pw[k:], pw[:k], "-a 7 mask+word")):
            wr = _word_rank(m, word)
            if not wr:
                continue
            mk = mask_of(aff)
            g = wr[0] * mask_keyspace(mk)
            if best is None or g < best.guesses:
                best = Result("Hybrid", f"hashcat {mode}", g,
                              f"{wr[1]} x mask {hc_mask(mk)} ({mask_keyspace(mk):,})")
    return best or Result("Hybrid", "hashcat -a 6 / -a 7", None, "no dictionary word + short mask split")


def _chain_count(logP, k):
    """# of k-tuples of ranks (>=1) whose product is <= P (continuous approximation)."""
    if k == 1:
        return math.exp(logP)
    # integral_0^t s^(k-1)/(k-1)! e^s ds
    t = logP
    P = math.exp(t)
    total = sum((-1) ** (k - 1 - j) * t ** j / math.factorial(j) for j in range(k)) * P
    total += (-1) ** k
    return max(total, 1.0)


def attack_prince(m, pw, max_k=6):
    n = len(pw)
    INF = float("inf")
    # cost[i][j] = log(rank) of pw[i:j] as a wordlist element (with case variants)
    seg = {}
    for i in range(n):
        for j in range(i + 1, min(n, i + 20) + 1):
            s = pw[i:j]
            wr = _word_rank(m, s)
            if wr:
                seg[(i, j)] = (math.log(wr[0] * 2), wr[1])   # x2: two merged wordlists
            if j - i <= 2 and all(not ch.isalnum() for ch in s):
                r = _rank_in(m.terms.get(("O", len(s))), s)    # separator, e.g. -j '$-'
                if r and ((i, j) not in seg or math.log(r[0]) < seg[(i, j)][0]):
                    seg[(i, j)] = (math.log(r[0]), f"separator '{s}' #{r[0]}")
    # dp[k][j] = (min log product using k elements for pw[:j], backpointer)
    dp = [[(INF, None)] * (n + 1) for _ in range(max_k + 1)]
    dp[0][0] = (0.0, None)
    for k in range(1, max_k + 1):
        for j in range(1, n + 1):
            bestv, bp = INF, None
            for i in range(max(0, j - 20), j):
                if (i, j) in seg and dp[k - 1][i][0] < INF:
                    v = dp[k - 1][i][0] + seg[(i, j)][0]
                    if v < bestv:
                        bestv, bp = v, i
            dp[k][j] = (bestv, bp)
    best = None
    for k in range(2, max_k + 1):
        lp = dp[k][n][0]
        if lp == INF:
            continue
        g = _chain_count(lp, k)
        if best is None or g < best[0]:
            parts, j, kk = [], n, k
            while kk > 0:
                i = dp[kk][j][1]
                parts.append(seg[(i, j)][1])
                j, kk = i, kk - 1
            best = (g, k, parts[::-1])
    # Passphrase with one repeated separator (e.g. Correct-Horse-Battery): the
    # separator is a single rule applied to the whole chain (-j '$-'), not an element.
    for sep in {ch for ch in pw if not ch.isalnum()}:
        parts = pw.split(sep)
        if len(parts) < 2 or not all(parts):
            continue
        ranks = [_word_rank(m, p) for p in parts]
        sr = _rank_in(m.terms.get(("O", 1)), sep)
        if not all(ranks) or not sr:
            continue
        lp = sum(math.log(r[0] * 2) for r in ranks) + math.log(sr[0])
        g = _chain_count(lp, len(parts))
        if best is None or g < best[0]:
            best = (g, len(parts), [r[1] for r in ranks] + [f"separator '{sep}' #{sr[0]}"])
    if not best:
        return Result("Combinator/PRINCE", "princeprocessor | hashcat", None,
                      "cannot be split into 2-6 wordlist elements")
    g, k, parts = best
    return Result("Combinator/PRINCE", "princeprocessor | hashcat", g,
                  f"{k} elements: " + " + ".join(parts))


# --- kwprocessor keyboard walks ---------------------------------------------
_ROWS = ["1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
_SHIFT = dict(zip("!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?",
                  "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"))
_KEYPOS = {}
for _r, _row in enumerate(_ROWS):
    for _c, _ch in enumerate(_row):
        _KEYPOS[_ch] = (_r, _c + 0.5 * _r)


def attack_kwalk(pw):
    if len(pw) < 4:
        return None
    base, shifted = [], 0
    for ch in pw:
        if ch in _SHIFT:
            base.append(_SHIFT[ch])
            shifted += 1
        elif ch in _KEYPOS:
            base.append(ch)
        else:
            return None
    dirs = []
    for a, b in zip(base, base[1:]):
        (r1, c1), (r2, c2) = _KEYPOS[a], _KEYPOS[b]
        dr, dc = r2 - r1, c2 - c1
        if abs(dr) > 1 or abs(dc) > 1.01:
            return None
        dirs.append((dr, round(dc * 2)))
    turns = sum(1 for a, b in zip(dirs, dirs[1:]) if a != b)
    L = len(pw)
    # start key x first direction x choice of turn positions x new direction at each turn
    g = 47 * 9 * math.comb(L - 2, turns) * 8 ** turns
    if shifted == L:
        g *= 2
    elif shifted:
        g *= 2 ** L
    return Result("Keyboard walk", "kwprocessor | hashcat", g // 2 + 1,
                  f"{L}-key walk with {turns} direction change(s)"
                  + (", shift used" if shifted else ""))


def attack_pcfg(m, pw):
    lp, parts = pcfg_parse(m, pw)
    if lp is None:
        return Result("PCFG", "pcfg_cracker", None, parts)
    return Result("PCFG", "pcfg_cracker", m.pcfg_mc.rank(lp), "; ".join(parts))


def attack_markov(m, pw):
    lp = markov_logp(m, pw)
    return Result("Markov", "JtR --incremental / OMEN", m.markov_mc.rank(lp),
                  f"3-gram probability 2^{lp / math.log(2):.1f}")


def analyze(m, pw, deep=True):
    rulesets = [m.rules[n] for n in ("best66", "leetspeak") if n in m.rules]
    if "best66" in m.rules and "leetspeak" in m.rules:
        if not hasattr(m, "_stack"):
            m._stack = RuleSet.stacked(m.rules["leetspeak"], m.rules["best66"])
        rulesets.append(m._stack)
    if deep:
        rulesets += [m.rules[n] for n in ("rockyou-30000", "dive") if n in m.rules]
    res = [attack_brute(pw), attack_mask(m, pw)]
    res += attack_dict(m, pw)
    res += attack_rules(m, pw, rulesets)
    res.append(attack_hybrid(m, pw))
    res.append(attack_prince(m, pw))
    kw = attack_kwalk(pw)
    if kw:
        res.append(kw)
    res.append(attack_pcfg(m, pw))
    res.append(attack_markov(m, pw))
    return res


# ===========================================================================
# Human-pattern commentary
# ===========================================================================

def _rank_in(counter_total, item):
    if counter_total is None:
        return None
    c, tot = counter_total
    v = c.get(item, 0)
    if not v:
        return None
    return 1 + sum(1 for x in c.values() if x > v), len(c), v / tot


def human_patterns(m, pw, res):
    out = []
    segs = SEG_RE.findall(pw)
    key = " ".join(f"{seg_class(s)}{len(s)}" for s in segs)
    sc = m.structs.get(key)
    if sc:
        rk = 1 + sum(1 for v in m.structs.values() if v > sc)
        out.append(f"layout {key} (A=letters D=digits O=symbols) is #{rk:,} of "
                   f"{len(m.structs):,} layouts in the leaked list")
    else:
        out.append(f"layout {key} never appears in the leaked list (good)")
    for i, s in enumerate(segs):
        cls, n = seg_class(s), len(s)
        where = "at the start" if i == 0 else "at the end" if i == len(segs) - 1 else "in the middle"
        if cls == "A":
            lo = s.lower()
            if n >= 3 and (lo in m.word_rank or lo in m.pw_rank):
                if lo in m.word_rank:
                    lang_name = LANGS[m.word_origin.get(lo, m.lang)][1]
                    src = f"{lang_name} word #{m.word_rank[lo]:,} in the {m.word_label} list"
                else:
                    src = f"leaked password #{m.pw_rank[lo]:,}"
                out.append(f"'{s}' is a dictionary word ({src})")
                if lo in m.word_orig:
                    out.append(f"'{s}' is '{m.word_orig[lo]}' typed without diacritics - attackers' "
                               f"Czech lists carry both forms, so this gains nothing")
            cm = s.translate(_CAPS_TT)
            if "U" in cm and n > 1:
                cc, _ = m.caps.get(n, (Counter(), 0))
                with_upper = sum(v for k, v in cc.items() if "U" in k)
                share = cc.get(cm, 0) / with_upper if with_upper else 0.0
                if cm == "U" + "L" * (n - 1):
                    what, cost = "first letter capitalized", "one rule (`c`) covers it: ~x2 work"
                elif cm == "U" * n:
                    what, cost = "ALL CAPS", "one rule (`u`) covers it: ~x2 work"
                else:
                    what, cost = "irregular capitalization", f"rules rarely cover it: up to x{2 ** n:,} work"
                out.append(f"'{s}': {what} - {share:.0%} of capitalized {n}-letter runs in leaks "
                           f"look exactly like this; {cost}")
        elif cls == "D":
            if n == 4 and s[:2] in ("19", "20"):
                out.append(f"'{s}' looks like a year {where}")
            r = _rank_in(m.terms.get(("D", n)), s)
            if r:
                out.append(f"'{s}' is the #{r[0]:,} most common {n}-digit run of {r[1]:,} "
                           f"({_pct(r[2])} of them) {where}")
        else:
            r = _rank_in(m.terms.get(("O", n)), s)
            if r:
                out.append(f"'{s}' {where} is the #{r[0]:,} most common {n}-symbol run "
                           f"({_pct(r[2])} of them)")
    # leet speak: a letter-bounded substring that un-leets to a known word
    leet_found = None
    for i in range(len(pw)):
        for j in range(len(pw), i + 3, -1):
            sub = pw[i:j].lower()
            if not (sub[0].isalpha() and sub[-1].isalpha() and set(sub[1:-1]) & set(LEET)):
                continue
            hits = [u for u in _unleet(sub) if u != sub and (u in m.word_rank or u in m.pw_rank)]
            if hits:
                best = min(hits, key=lambda u: (sum(ch in LEET for ch in u), -len(u)))
                if leet_found is None or j - i > len(leet_found[0]):
                    leet_found = (pw[i:j], best)
    if leet_found:
        out.append(f"'{leet_found[0]}' is leet for '{leet_found[1]}' - leetspeak rules "
                   f"(sa@ so0 se3 ...) are in every rule set, this adds very little")
    for r in res:
        if r.attack == "Keyboard walk":
            out.append(f"keyboard walk: {r.detail}")
    return list(dict.fromkeys(out))


def _pct(x):
    return f"{x:.0%}" if x >= 0.095 else f"{x:.1%}" if x >= 0.001 else f"{x:.3%}"


# ===========================================================================
# Reporting
# ===========================================================================

# Approximate single-GPU speeds (hashcat 6.2.6 benchmark, NVIDIA RTX 4090).
HASH_RATES = [
    ("NTLM (Windows)", 288.5e9),
    ("MD5", 164.1e9),
    ("SHA-1", 50.6e9),
    ("SHA-256", 21.98e9),
    ("sha512crypt", 1.18e6),
    ("WPA2 (PBKDF2)", 2.53e6),
    ("bcrypt cost 10", 184e3 / 32),
    ("bcrypt cost 12", 184e3 / 128),
    ("scrypt N=16384", 7126),
    ("online, 10/s", 10),
]

# Passphrase-protected SSH private keys. The key's `-----BEGIN ...-----` banner
# tells you the format; each uses a different KDF, so the SAME passphrase is
# cracked at wildly different speeds. Rates are per RTX 4090.
_BCRYPT5 = 184.0e3  # hashcat bcrypt $2*$ benchmark, cost 5 (32 iterations)
SSH_RATES = [
    # New OpenSSH format (default since OpenSSH 7.8): bcrypt_pbkdf. Default 16
    # rounds ~= 1024 Blowfish key setups ~= 32x a cost-5 bcrypt op. Estimate.
    ("new OpenSSH (bcrypt_pbkdf, 16 rounds)", _BCRYPT5 / 32, "est."),
    # PKCS#8 'BEGIN ENCRYPTED PRIVATE KEY': PBES2 with PBKDF2. Assume
    # HMAC-SHA256 at OpenSSL's old default of 2048 iterations. Estimate.
    ("PKCS#8 (PBKDF2-SHA256, 2048 iters)", 21.98e9 / (2 * 2048), "est."),
    # Legacy PEM 'BEGIN RSA PRIVATE KEY' + DEK-Info: OpenSSL EVP_BytesToKey,
    # one pass of MD5. hashcat -m 22911 (AES-128-CBC) benchmark.
    ("legacy PEM (MD5 KDF, 1 pass)", 4382.6e6, "hashcat -m 22911"),
]

# Active Directory service tickets (Kerberoasting / AS-REP roasting). The
# etype decides the speed: RC4 tickets are keyed on the NT hash itself (one
# MD4 + HMAC-MD5, essentially NTLM speed), while AES tickets add PBKDF2-
# HMAC-SHA1 with 4096 iterations. Rates are per RTX 4090, hashcat benchmark.
KERBEROS_RATES = [
    ("NTLM hash (for reference)", 288.5e9, "hashcat -m 1000"),
    ("Kerberoast RC4 (TGS-REP etype 23)", 3478.0e6, "hashcat -m 13100"),
    ("Kerberoast AES (TGS-REP etype 18)", 2562.9e3, "hashcat -m 19700"),
]


def fmt_num(x):
    if x is None:
        return "-"
    if x < 1e6:
        return f"{int(round(x)):,}"
    return f"{float(x):.2e}" if x < 1e300 else f"1e{math.log10(x):.0f}"


def fmt_time(sec):
    if sec < 1:
        return "instant"
    units = [("seconds", 60), ("minutes", 60), ("hours", 24), ("days", 365.25), ("years", None)]
    v = sec
    for name, step in units:
        if step is None or v < step:
            if name == "years" and v >= 1e6:
                return f"{v:.1e} years"
            return f"{v:,.0f} {name}" if v >= 10 else f"{v:.1f} {name}"
        v /= step


def verdict(lg):
    if lg < 6:
        return "VERY WEAK - falls to an online attack or the first second of any offline one"
    if lg < 10:
        return "WEAK - instant against fast hashes (MD5/NTLM/SHA), hours-weeks against bcrypt"
    if lg < 14:
        return "FAIR - minutes-hours against fast hashes; decent only behind slow hashes"
    if lg < 18:
        return "GOOD - weeks+ against fast hashes on one GPU; a large rig could still get it"
    return "STRONG - beyond the reach of every modelled attack"


def report(m, pw, res, gpus, show_pw, verbose=False):
    """Print the report. Without show_pw it prints no text taken from the password:
    no characters, no mask, and none of the per-attack details or human patterns,
    because those name the matched words, rules and segments and so spell the
    password out. Only its length, the guess numbers and the time tables remain."""
    found = [r for r in res if r.guesses is not None]
    best = min(found, key=lambda r: r.guesses)
    print()
    if show_pw:
        print(f"Password  {pw}   length {len(pw)}   mask {hc_mask(mask_of(pw))}   "
              f"words: {m.word_label}")
    else:
        print(f"Password  {'*' * len(pw)}   length {len(pw)}   words: {m.word_label}")
    print()
    print(f"  {'attack':<18} {'guesses':>10}  {'log10':>5}  tool / how")
    print("  " + "-" * 92)
    for r in sorted(found, key=lambda r: r.guesses):
        if not verbose and r.attack == "Dict + rules" and r is not best and any(
                o.attack == r.attack and o.guesses < r.guesses for o in found):
            continue          # only the best rules attack unless --verbose
        lg = f"{math.log10(max(r.guesses, 1)):5.1f}"
        mark = "*" if r is best else " "
        print(f"{mark} {r.attack:<18} {fmt_num(r.guesses):>10}  {lg}  {r.tool}")
        if show_pw:
            print(f"  {'':<18} {'':>10}         {r.detail}")
    missed = [r for r in res if r.guesses is None]
    never = sorted({r.attack for r in missed
                    if all(o.guesses is None for o in res if o.attack == r.attack)},
                   key=[r.attack for r in res].index)
    if missed:
        print("  " + "-" * 92)
        if never:
            print("  never produced by: " + ", ".join(never))
        if verbose:
            for r in missed:
                print(f"    {r.tool}" + (f": {r.detail}" if show_pw else ""))
    lg = math.log10(max(best.guesses, 1))
    print()
    if show_pw:
        print("Human patterns spotted:")
        for line in human_patterns(m, pw, res):
            print(f"  - {line}")
    else:
        print("Details hidden: they name the words, rules and characters each attack")
        print("matched, which spells out the password. Rerun with --show to see them.")
    print()
    print(f"Estimated guesses: {fmt_num(best.guesses)} (10^{lg:.1f}) via {best.attack}  [{best.tool}]")
    print(f"Verdict: {verdict(lg)}")
    print()
    print(f"Average time to crack with {gpus} x RTX 4090 (hashcat benchmark speeds):")
    for name, rate in HASH_RATES:
        r = rate * (gpus if not name.startswith("online") else 1)
        print(f"  {name:<16} {fmt_time(float(best.guesses) / r):>18}")
    print()
    print("If this were an SSH private-key passphrase (format is in the key's")
    print("-----BEGIN----- banner; same passphrase, different KDF):")
    for name, rate, src in SSH_RATES:
        t = fmt_time(float(best.guesses) / (rate * gpus))
        print(f"  {name:<38} {t:>18}   [{src}]")
    print()
    print("If this were an Active Directory account (cracked offline from a stolen")
    print("Kerberos service ticket, i.e. Kerberoasting; AS-REP roasting is the same):")
    for name, rate, src in KERBEROS_RATES:
        t = fmt_time(float(best.guesses) / (rate * gpus))
        print(f"  {name:<38} {t:>18}   [{src}]")
    print()


def _readable_struct(key):
    name = {"A": "letters", "D": "digits", "O": "symbols"}
    parts = []
    for tok in key.split():
        n = int(tok[1:])
        parts.append(f"{n} {name[tok[0]]}" if n > 1 else f"1 {name[tok[0]][:-1]}")
    return " + ".join(parts)


def print_patterns(m, top=15):
    """Print the habits the model learned from the leaked list, so people can see
    what to avoid. Reads no password; pure statistics from the training data."""
    tot = m.structs_total
    bar = "=" * 78

    print(f"\n{bar}\nMost common password habits in {m.pw_size:,} leaked passwords")
    print("These are what to AVOID. (This report is the same in every --lang: it")
    print(f"comes from the leaked list, not the dictionary.)\n{bar}")

    print("\n# The most-reused passwords (never use one of these)")
    for i, p in enumerate(sorted(m.pw_rank, key=m.pw_rank.get)[:20], 1):
        print(f"  {i:>2}. {p}")

    print("\n# The most common layouts (where letters/digits/symbols go)")
    print("  Over half of all passwords follow one of just a handful of shapes.")
    for key, cnt in m.structs.most_common(top):
        print(f"  {cnt / tot:6.1%}  {_readable_struct(key):<34} e.g. {_struct_example(m, key)}")

    print("\n# If you add ONE symbol, it is almost always one of these")
    sy, st = m.terms.get(("O", 1), (Counter(), 1))
    for ch, cnt in sy.most_common(12):
        print(f"  {cnt / st:6.1%}  {ch!r}")
    print("  -> a symbol only helps if it is not '!' '.' '@' '_' '-' and not at the end.")

    print("\n# Where the symbol goes, when there is exactly one")
    _print_affix_position(m)

    print("\n# The most common digit endings")
    for n in (1, 2, 4):
        c, t = m.terms.get(("D", n), (Counter(), 1))
        common = ", ".join(f"{d}" for d, _ in c.most_common(8))
        print(f"  {n}-digit:  {common}")
    years = [(d, cnt) for d, cnt in m.terms.get(("D", 4), (Counter(), 1))[0].items()
             if d[:2] in ("19", "20")]
    years.sort(key=lambda x: -x[1])
    print("  Of 4-digit runs, birth/recent years dominate: "
          + ", ".join(d for d, _ in years[:10]))

    print("\n# Capitalization habits (for words that have any capital letter)")
    _print_caps(m)

    print("\n# The most common base words people build on")
    print("  (from the leak, which is heavy on English and Russian; the odd-looking")
    print("   ones like 'vfvf' are Russian words typed on a QWERTY keyboard layout)")
    seen, shown = set(), 0
    for n in range(4, 9):
        c, _ = m.terms.get(("A", n), (Counter(), 0))
        for w, _cnt in c.most_common():
            if w in seen:
                continue
            seen.add(w)
            print(f"  {w}")
            shown += 1
            if shown % 6 == 0 or shown >= 18:
                break
        if shown >= 18:
            break

    print(f"\n{bar}\nTakeaways")
    print(bar)
    for line in (
        "A longer password beats a complicated short one. Length is the only thing",
        "  brute force cannot shortcut; everything above is a shortcut attackers use.",
        "Four or more random, unrelated words beat 'Word123!'.",
        "A capital at the front and a digit/symbol at the end add almost nothing:",
        "  the cracking rules try exactly those first.",
        "Leet substitutions (a->@, o->0, s->$) are built into every rule set.",
        "Avoid years, '123', keyboard walks (qwerty, 1qaz), and real words you'd pick.",
    ):
        print(f"  {line}")
    print()


def _struct_example(m, key):
    out = []
    for tok in key.split():
        cls, n = tok[0], int(tok[1:])
        c, _ = m.terms.get((cls, n), (Counter(), 0))
        top = c.most_common(1)
        piece = top[0][0] if top else "?" * n
        if cls == "A":
            cc, _ = m.caps.get(n, (Counter(), 0))
            mask = cc.most_common(1)
            if mask:
                piece = "".join(ch.upper() if f == "U" else ch
                                for ch, f in zip(piece, mask[0][0]))
        out.append(piece)
    return "".join(out)


def _print_affix_position(m):
    start = mid = end = 0
    for p in list(m.pw_rank)[:50000]:
        segs = SEG_RE.findall(p)
        osegs = [i for i, s in enumerate(segs) if seg_class(s) == "O"]
        if len(osegs) != 1 or sum(1 for ch in p if not ch.isalnum()) != 1:
            continue
        i = osegs[0]
        if i == 0:
            start += 1
        elif i == len(segs) - 1:
            end += 1
        else:
            mid += 1
    tot = max(start + mid + end, 1)
    print(f"  {end / tot:6.1%}  at the very end      "
          f"{start / tot:6.1%}  at the very start      {mid / tot:6.1%}  in the middle")


def _print_caps(m):
    agg = Counter()
    for n, (c, _t) in m.caps.items():
        if n < 2:
            continue
        for mask, cnt in c.items():
            if "U" not in mask:
                label = None
            elif mask[0] == "U" and "U" not in mask[1:]:
                label = "only the first letter capital (Word)"
            elif set(mask) == {"U"}:
                label = "ALL CAPS (WORD)"
            elif mask[-1] == "U" and "U" not in mask[:-1]:
                label = "only the last letter capital (worD)"
            else:
                label = "some other mix (wOrD)"
            if label:
                agg[label] += cnt
    tot = max(sum(agg.values()), 1)
    for label, cnt in agg.most_common():
        print(f"  {cnt / tot:6.1%}  {label}")


def read_password(args):
    if args.stdin or not sys.stdin.isatty():
        return [line.rstrip("\r\n") for line in sys.stdin if line.strip()]
    pw = getpass.getpass("Password (not echoed): ")
    return [pw] if pw else []


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lang", choices=list(LANGS), default="en",
                    help="word dictionary the attacker uses: en, cs, or mixed (English+Czech "
                         "interleaved by frequency). Default: en")
    ap.add_argument("--patterns", action="store_true",
                    help="print the most common habits to avoid, then exit (reads no password)")
    ap.add_argument("--stdin", action="store_true", help="read one password per line from stdin")
    ap.add_argument("--fast", action="store_true", help="skip the big rule files (rockyou-30000, dive)")
    ap.add_argument("--gpus", type=int, default=1, help="number of RTX-4090-class GPUs for the time table")
    ap.add_argument("--show", action="store_true",
                    help="print the password, its mask, and each attack's details and the human "
                         "patterns (these name the matched words and characters)")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every attack, including misses")
    args = ap.parse_args()

    def log(msg):
        print(msg, file=sys.stderr)

    # Czech diacritics: make piped/redirected I/O UTF-8 instead of the Windows code page.
    for stream in (sys.stdout, sys.stdin):
        if hasattr(stream, "reconfigure") and not stream.isatty():
            stream.reconfigure(encoding="utf-8", errors="replace")

    m = load_model(log, args.lang)
    if args.patterns:
        print_patterns(m)
        return
    pws = read_password(args)
    for pw in pws:
        t0 = time.time()
        res = analyze(m, pw, deep=not args.fast)
        report(m, pw, res, args.gpus, args.show, args.verbose)
        print(f"(analysis took {time.time() - t0:.1f}s; nothing left this machine)")


if __name__ == "__main__":
    main()

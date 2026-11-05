#!/usr/bin/env python3
"""pwguess - estimate how many guesses real cracking tools would need for a password.

Fully offline: the network is disabled at startup, the password is read without
echo, never written anywhere, and no hash is ever computed or cracked. The
program only asks "at what position would attack X produce this exact string?"

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
# Network guard: nothing below may open a socket.
import socket as _socket


def _no_network(*_a, **_k):
    raise RuntimeError("pwguess: network access is disabled in this program")


class _NoSocket(_socket.socket):
    def __init__(self, *_a, **_k):
        _no_network()


_socket.socket = _NoSocket
_socket.create_connection = _no_network
_socket.getaddrinfo = _no_network
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
from collections import Counter
from itertools import accumulate

from hcrules import RuleSet

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
RULES = os.path.join(HERE, "rules")
PW_FILE = os.path.join(DATA, "passwords.txt")
EN_FILE = os.path.join(DATA, "en_words.txt")
CACHE = os.path.join(DATA, "model_cache.pkl")
CACHE_VERSION = 4

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


def train(log):
    m = Model()
    t0 = time.time()
    pw_list = list(read_lines(PW_FILE))
    m.pw_rank = {}
    for i, p in enumerate(pw_list, 1):
        m.pw_rank.setdefault(p, i)
    m.pw_size = len(m.pw_rank)

    m.en_rank = {}
    for line in read_lines(EN_FILE):
        w = line.split()[0].lower()
        if w not in m.en_rank:
            m.en_rank[w] = len(m.en_rank) + 1
    m.en_size = len(m.en_rank)
    log(f"  wordlists loaded: {m.pw_size:,} passwords, {m.en_size:,} English words")

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

    en_by_len = {}
    for w, r in m.en_rank.items():
        if w.isascii() and w.isalpha():
            en_by_len.setdefault(len(w), []).append((r, w))
    m.en_len_z = {n: sum(1.0 / r for r, _ in lst) for n, lst in en_by_len.items()}
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
    m.pcfg_mc = MonteCarlo(_sample_pcfg(m, rng, en_by_len, MC_SAMPLES))
    m.markov_mc = MonteCarlo(_sample_markov(m, rng, MC_SAMPLES))
    log(f"  Monte Carlo: {MC_SAMPLES:,} samples each  ({time.time() - t0:.1f}s total)")

    m.rules = {}
    for name in RULE_FILES:
        path = os.path.join(RULES, name + ".rule")
        if os.path.exists(path):
            m.rules[name] = RuleSet.from_file(path)
    return m


def load_model(log):
    stamp = [CACHE_VERSION]
    for p in [PW_FILE, EN_FILE] + [os.path.join(RULES, r + ".rule") for r in RULE_FILES]:
        stamp.append((os.path.basename(p), os.path.getsize(p) if os.path.exists(p) else -1))
    if os.path.exists(CACHE):
        try:
            with open(CACHE, "rb") as f:
                saved_stamp, m = pickle.load(f)
            if saved_stamp == stamp:
                return m
        except Exception:
            pass
    for p in (PW_FILE, EN_FILE):
        if not os.path.exists(p):
            sys.exit(f"missing {os.path.relpath(p, HERE)} - run `python fetch_data.py` first")
    log("Training models from the wordlists (first run only, ~1 min)...")
    m = train(log)
    with open(CACHE, "wb") as f:
        pickle.dump((stamp, m), f, protocol=pickle.HIGHEST_PROTOCOL)
    return m


# ===========================================================================
# PCFG probability + sampling
# ===========================================================================

EN_SHARE = 0.8  # share of the alpha back-off mass given to the English dictionary


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
            back = (1 - EN_SHARE) * 26.0 ** -n
            if n in m.en_len_z and lw in m.en_rank:
                back += EN_SHARE * (1.0 / m.en_rank[lw]) / m.en_len_z[n]
            elif n not in m.en_len_z:
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


def _sample_pcfg(m, rng, en_by_len, k):
    skeys = list(m.structs)
    scum = list(accumulate(m.structs[s] for s in skeys))
    tcache = {}

    def cum(table, key):
        if key not in tcache:
            c, _ = table[key]
            items = list(c)
            tcache[key] = (items, list(accumulate(c[i] for i in items)))
        return tcache[key]

    en_cum = {}
    for n, lst in en_by_len.items():
        lst.sort()
        en_cum[n] = ([w for _, w in lst], list(accumulate(1.0 / r for r, _ in lst)))

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
                if n in en_cum and rng.random() < EN_SHARE:
                    items, cw = en_cum[n]
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
    g = sum(95 ** i for i in range(1, n)) + (95 ** n) // 2
    note = "" if all(c in PRINTABLE for c in pw) else " (non-ASCII chars: not in ?a, would never be found)"
    return Result("Brute force", "hashcat -a 3 -i ?a" + "?a" * (n - 1), g,
                  f"all 95-char strings up to length {n}{note}")


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
    r = m.en_rank.get(pw)
    out.append(Result("Dictionary", "hashcat -a 0 en_words.txt", r,
                      f"rank {r:,} in English word list" if r else "not in English word list"))
    return out


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
    for wl_name, rank in (("passwords.txt", m.pw_rank), ("en_words.txt", m.en_rank)):
        words = sorted((rank[w], w) for w in cands if w in rank)
        for rs in rulesets:
            res = None
            for r, w in words:
                if (r - 1) * rs.size > 1e18:
                    break
                idx = rs.first_match(w, pw)
                if idx is not None:
                    g = (r - 1) * rs.size + idx + 1
                    res = Result("Dict + rules", f"hashcat -a 0 {wl_name} -r {rs.name}.rule", g,
                                 f"base '{w}' (rank {r:,}) x rule #{idx + 1} `{rs.texts[idx]}` "
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
        for name, rank in (("pw", m.pw_rank), ("en", m.en_rank)):
            r = rank.get(variant)
            if r and (best is None or r * factor < best[0]):
                best = (r * factor, f"'{variant}' rank {r:,} ({name}){how}")
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
            if n >= 3 and (lo in m.en_rank or lo in m.pw_rank):
                src = (f"English word #{m.en_rank[lo]:,}" if lo in m.en_rank
                       else f"leaked password #{m.pw_rank[lo]:,}")
                out.append(f"'{s}' is a dictionary word ({src})")
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
            hits = [u for u in _unleet(sub) if u != sub and (u in m.en_rank or u in m.pw_rank)]
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
    found = [r for r in res if r.guesses is not None]
    best = min(found, key=lambda r: r.guesses)
    shown = pw if show_pw else (pw[0] + "*" * (len(pw) - 2) + pw[-1] if len(pw) > 2 else "*" * len(pw))
    mk = mask_of(pw)
    print()
    print(f"Password  {shown}   length {len(pw)}   mask {hc_mask(mk)}")
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
                print(f"    {r.tool}: {r.detail}")
    lg = math.log10(max(best.guesses, 1))
    print()
    print("Human patterns spotted:")
    for line in human_patterns(m, pw, res):
        print(f"  - {line}")
    print()
    print(f"Estimated guesses: {fmt_num(best.guesses)} (10^{lg:.1f}) via {best.attack}  [{best.tool}]")
    print(f"Verdict: {verdict(lg)}")
    print()
    print(f"Average time to crack with {gpus} x RTX 4090 (hashcat benchmark speeds):")
    for name, rate in HASH_RATES:
        r = rate * (gpus if not name.startswith("online") else 1)
        print(f"  {name:<16} {fmt_time(float(best.guesses) / r):>18}")
    print()


def read_password(args):
    if args.stdin or not sys.stdin.isatty():
        return [line.rstrip("\r\n") for line in sys.stdin if line.strip()]
    pw = getpass.getpass("Password (not echoed): ")
    return [pw] if pw else []


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stdin", action="store_true", help="read one password per line from stdin")
    ap.add_argument("--fast", action="store_true", help="skip the big rule files (rockyou-30000, dive)")
    ap.add_argument("--gpus", type=int, default=1, help="number of RTX-4090-class GPUs for the time table")
    ap.add_argument("--show", action="store_true", help="print the password itself in the report")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every attack, including misses")
    args = ap.parse_args()

    def log(msg):
        print(msg, file=sys.stderr)

    m = load_model(log)
    pws = read_password(args)
    for pw in pws:
        t0 = time.time()
        res = analyze(m, pw, deep=not args.fast)
        report(m, pw, res, args.gpus, args.show, args.verbose)
        print(f"(analysis took {time.time() - t0:.1f}s; nothing left this machine)")


if __name__ == "__main__":
    main()

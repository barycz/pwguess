# pwguess: how many guesses would real cracking tools need?

`pwguess` reads a password and estimates its **guess number**: how many candidates
each common cracking strategy produces before it reaches that exact string. It also
converts the best (lowest) number into time at real GPU hash rates.

It is completely offline. The script turns off Python's socket module when it
starts, reads the password without echoing it, and never writes it anywhere. It
never computes or cracks a hash. All it asks is: *at what position would attack X
produce this string?*

## Usage

```bash
python fetch_data.py          # one time: downloads wordlists + hashcat rules (~10 MB)
python pwguess.py             # prompts for a password (hidden input)
```

Options: `--fast` (skip the big rule files), `--gpus 8` (time table for a rig),
`--show` (print the password in the report instead of masking it), `-v` (list
every attack, including misses), `--stdin` (read one password per line from
stdin). Piping passwords in can leave them in your shell history, so prefer the
prompt.

The first run trains the models (~25 s) and caches them in `data/model_cache.pkl`.
Later runs start in ~2 s.

## What is modelled

Each attack is estimated on its own. The reported strength is the **minimum**
across all of them, which is the "min_auto" method from Ur et al., *Measuring
Real-World Accuracies and Biases in Modeling Password Guessability* (USENIX
Security 2015). They found it tracks professional crackers well.

| Attack | Real tool | How the guess number is computed |
|---|---|---|
| Brute force | `hashcat -a 3 -i ?a?a…` | Exact: every ?a string of shorter length, plus half of this length |
| Mask | `hashcat -a 3` with PACK `statsgen`/`maskgen` masks | Masks learned from the leak list, sorted by PACK's optindex (hits ÷ keyspace). Counts the keyspace of every earlier mask, plus half of this one |
| Dictionary | `hashcat -a 0` | Rank in the leak list / English list |
| Dict + rules | `hashcat -a 0 -r best66 / leetspeak / leetspeak×best66 / rockyou-30000 / dive` | The **real hashcat rule files**, run by an included rule engine (`hcrules.py`). hashcat applies every rule to each word, so the guess number is `(rank−1)·|rules| + rule index` |
| Hybrid | `hashcat -a 6` / `-a 7` | Word rank × keyspace of the digit/symbol mask added before or after it (×2 if a `-j c`/`-j u` case rule is needed) |
| Combinator / PRINCE | `hashcat -a 1`, `princeprocessor` | Splits the password into the cheapest chain of 2-6 wordlist entries, or words joined by one separator. Counts the chains whose rank product is no larger than this one (an ideal, probability-ordered combinator) |
| Keyboard walk | `kwprocessor` | Start key × directions × positions of direction changes |
| PCFG | Weir's `pcfg_cracker` | Grammar trained on the leak list: layout (e.g. `A6 D4 O1`) × capitalization mask × word/digit/symbol pieces, with Witten-Bell back-off to the English list |
| Markov | JtR `--incremental`, OMEN, hashcat `.hcstat2` | Character 3-gram model trained on the leak list |

For PCFG and Markov, the guess number comes from the Monte Carlo estimator of
Dell'Amico & Filippone (*Monte Carlo Strength Evaluation*, CCS 2015). It takes
100k samples from the model and estimates the password's rank as
`Σ 1/(n·pᵢ)` over the samples that are more likely than it. This gives the
password's position in a probability-ordered enumeration without enumerating it.

The report also has a **"Human patterns spotted"** section, with leak statistics for
the habits you'd expect: a capitalized first letter (about half of all capitalized
words in leaks), years, `123`, a trailing `!` or `.` (`.` is the #2 single
symbol), leetspeak, and keyboard walks.

## Data (downloaded by `fetch_data.py`)

- `data/passwords.txt`: SecLists `xato-net-10-million-passwords-1000000.txt`
  (top 1M passwords, ranked by frequency)
- `data/en_words.txt`: hermitdave/FrequencyWords `en_50k.txt`
  (English words ranked by subtitle frequency)
- `rules/*.rule`: hashcat's own `best66`, `leetspeak`, `rockyou-30000` and `dive`

You can swap in bigger lists, e.g. rockyou (14M) as `data/passwords.txt` or another
`.rule` file named in `RULE_FILES`. The cache rebuilds by itself when they change.

## Limitations and how to read the numbers

- **min_auto is optimistic for the attacker.** It assumes they run the attack that
  works first. Real attackers run a sequence of attacks, so actual cost can be the
  sum of the earlier stages.
- **The leak list is from around 2015 and mostly lowercase.** Only ~9% of entries
  contain an uppercase letter and ~1% a symbol. PCFG and mask statistics therefore
  under-weight "policy" passwords like `Summer2024!`. Crackers attacking a site with
  a policy filter their training data (PACK `policygen`), so the true PCFG numbers
  for such passwords are lower. The hybrid and rule attacks still catch them.
- **Dictionaries are finite.** Words outside the 50k English list or the 1M leak list
  (rare words, names, other languages) look stronger here than they would against
  a cracker with bigger lists.
- Monte Carlo estimates are accurate to within a factor of a few, not to the digit.
- Times are averages for one RTX 4090 at hashcat 6.2.6 benchmark speeds
  (MD5 164 GH/s, NTLM 288 GH/s, bcrypt cost 10 ≈ 5.75 kH/s). Online attacks are
  shown at 10 guesses/s.

## Files

- `pwguess.py`: estimator (stdlib only, Python 3.8+)
- `hcrules.py`: hashcat/JtR rule-language engine
- `fetch_data.py`: one-time downloader, the only code that touches the network

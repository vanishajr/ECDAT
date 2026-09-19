"""Phase 14 tests: mutation robustness (additive).

Each test takes one representative crypto operation and checks that
syntactic mutations (aliases, wrappers, import styles, field storage,
split init/use, branches) produce *equivalent semantic results* through
the real Phase 2 fact layer (:mod:`ecdat.scanners.source.facts`) and the
real Phase 3 demand-driven resolver (:mod:`ecdat.scanners.source.resolver`).

Convention: hand-built assignment facts carry quoted literals
(``'"AES-256-GCM"'``), matching the established resolver contract also
used by ``test_phase2_3_5_8.py``; structural facts (calls, wrappers,
imports) are extracted from real source strings. The resolver is
conservative by design: anything ungrounded returns ``None`` rather than
a guess, so several tests assert equivalent ``None`` (no divergence, no
guessing) alongside equivalent positive resolutions.
"""

from __future__ import annotations

from ecdat.scanners.source import facts as F
from ecdat.scanners.source import resolver as R

ALGO = "AES-256-GCM"


def _assign(name: str, value: object, line: int = 1,
            kind: str = "assignment") -> F.SourceFact:
    return F.SourceFact(kind=kind, language="py", name=name,
                        file="m.py", line=line, value=value)


def _call(name: str, args: tuple, line: int = 9,
          function: str | None = None) -> F.SourceFact:
    return F.SourceFact(kind="function_call", language="py", name=name,
                        file="m.py", line=line, function=function,
                        arguments=args)


def _def(name: str, line: int = 1) -> F.SourceFact:
    return F.SourceFact(kind="function_definition", language="py",
                        name=name, file="m.py", line=line)


def _algo_of(call: F.SourceFact, facts: list[F.SourceFact]) -> object:
    hit = R.resolve_algorithm(call, facts)
    return hit.value if hit is not None else None


# 1. direct call -----------------------------------------------------------

def test_01_direct_call_literal_resolves():
    call = _call("encrypt", (f'"{ALGO}"',))
    assert _algo_of(call, []) == ALGO


# 2. variable alias --------------------------------------------------------

def test_02_variable_alias_equivalent_to_direct():
    facts = [_assign("ALGO", f'"{ALGO}"')]
    mutated = _call("encrypt", ("ALGO",))
    baseline = _call("encrypt", (f'"{ALGO}"',))
    assert _algo_of(mutated, facts) == _algo_of(baseline, []) == ALGO


# 3. constant alias (AnnAssign-style constant fact) ------------------------

def test_03_constant_alias_equivalent_to_variable():
    var_facts = [_assign("ALGO", f'"{ALGO}"')]
    const_facts = [_assign("ALGO", f'"{ALGO}"', kind="constant")]
    call = _call("encrypt", ("ALGO",))
    assert _algo_of(call, const_facts) == _algo_of(call, var_facts) == ALGO


# 4. chained alias (two-hop variable indirection) --------------------------

def test_04_chained_alias_two_hop():
    facts = [_assign("A", f'"{ALGO}"', line=1),
             _assign("B", "A", line=2)]
    assert _algo_of(_call("encrypt", ("B",)), facts) == ALGO
    direct = R.resolve_value("B", facts)
    assert direct is not None and direct.value == ALGO
    assert direct.hops >= 1  # indirection costs confidence, not correctness


# 5. function wrapper (single hop) -----------------------------------------

def test_05_function_wrapper_expands_to_direct_call():
    src = 'def wrap():\n    encrypt("AES-256-GCM")\nwrap()\n'
    facts = F.extract_facts_python(src, "m.py")
    expansion = R.expand_wrapper("wrap", facts)
    assert expansion is not None
    assert expansion.target == "encrypt"  # same callee as the direct call
    assert any(f.kind == "function_call" and f.name == "encrypt"
               for f in facts)


# 6. two-hop wrapper --------------------------------------------------------

def test_06_two_hop_wrapper_reaches_same_target():
    src = ('def inner():\n    encrypt("AES-256-GCM")\n'
           'def outer():\n    inner()\nouter()\n')
    facts = F.extract_facts_python(src, "m.py")
    one = R.expand_wrapper("inner", facts)
    two = R.expand_wrapper("outer", facts)
    assert one is not None and two is not None
    assert one.target == two.target == "encrypt"
    assert two.hops > one.hops
    assert two.confidence < one.confidence  # decay per hop, same target


# 7. helper-returned algo: no guessing -------------------------------------

def test_07_helper_returned_algo_never_guessed():
    single = ('def get_algo():\n    return "AES-256-GCM"\n'
              'ALGO = get_algo()\nencrypt(ALGO)\n')
    nested = ('def base():\n    return "AES-256-GCM"\n'
              'def get_algo():\n    return base()\n'
              'ALGO = get_algo()\nencrypt(ALGO)\n')
    results = []
    for src in (single, nested):
        facts = F.extract_facts_python(src, "m.py")
        calls = [f for f in facts if f.kind == "function_call"
                 and f.name == "encrypt"]
        assert len(calls) == 1
        results.append(_algo_of(calls[0], facts))
    assert results == [None, None]  # equivalent: ungrounded, no guess


# 8. helper-returned / stored key size --------------------------------------

def test_08_key_size_alias_forms_agree():
    int_assign = [_assign("BITS", 2048)]
    macro_style = [_assign("BITS", "2048", kind="macro")]
    for facts in (int_assign, macro_style):
        call = _call("rsa_generate", ("BITS",))
        hit = R.resolve_key_size(call, facts)
        assert hit is not None and hit.value == 2048
    # Bare literal in a complex expression is not guessed (conservative).
    assert R.resolve_key_size(
        _call("rsa_generate", ("2048",)), []) is None


# 9. mode literal vs alias ---------------------------------------------------

def test_09_mode_literal_vs_alias():
    alias_facts = [_assign("MODE", '"GCM"')]
    via_alias = R.resolve_mode(_call("encrypt", ("MODE",)), alias_facts)
    via_literal = R.resolve_mode(_call("encrypt", ('"GCM"',)), [])
    assert via_literal is not None and via_literal.value == "GCM"
    assert via_alias is not None and via_alias.value == "GCM"


# 10. curve literal vs alias --------------------------------------------------

def test_10_curve_literal_vs_alias():
    alias_facts = [_assign("CURVE", '"secp256r1"')]
    via_alias = R.resolve_curve(_call("do_ecdh", ("CURVE",)), alias_facts)
    via_literal = R.resolve_curve(_call("do_ecdh", ('"secp256r1"',)), [])
    assert via_literal is not None and via_literal.value == "secp256r1"
    assert via_alias is not None and via_alias.value == "secp256r1"


# 11. import alias -------------------------------------------------------------

def test_11_import_alias_points_at_same_module():
    plain = F.extract_facts_python("import hashlib\nhashlib.sha256(b'x')\n",
                                   "m.py")
    aliased = F.extract_facts_python(
        "import hashlib as hl\nhl.sha256(b'x')\n", "m.py")
    plain_mods = {f.metadata.get("module")
                  for f in plain if f.kind == "import"}
    alias_mods = {f.metadata.get("module")
                  for f in aliased if f.kind == "import"}
    assert plain_mods == alias_mods == {"hashlib"}
    # One call fact per variant; the plain callee names its provider.
    plain_calls = [f for f in plain if f.kind == "function_call"]
    alias_calls = [f for f in aliased if f.kind == "function_call"]
    assert len(plain_calls) == len(alias_calls) == 1
    assert R.resolve_provider(plain_calls[0]) is not None
    assert R.resolve_provider(plain_calls[0]).value == "hashlib"


# 12. separated init/use (scope fallback + noise) ------------------------------

def test_12_separated_init_and_use():
    baseline = [_assign("ALGO", f'"{ALGO}"', line=1),
                _call("encrypt", ("ALGO",), line=2)]
    mutated = [_assign("ALGO", f'"{ALGO}"', line=1),
               _assign("NOISE", '"hello"', line=2),
               _call("log", ("NOISE",), line=3, function="run"),
               _call("encrypt", ("ALGO",), line=9, function="run")]
    assert _algo_of(baseline[-1], baseline) == ALGO
    assert _algo_of(mutated[-1], mutated) == ALGO  # module scope fallback


# 13. conditional branch (same value both arms) ---------------------------------

def test_13_conditional_branch_same_value():
    baseline = [_assign("ALGO", f'"{ALGO}"', line=1)]
    branched = [_assign("ALGO", f'"{ALGO}"', line=2),
                _assign("ALGO", f'"{ALGO}"', line=4)]
    call = _call("encrypt", ("ALGO",), line=6)
    assert _algo_of(call, branched) == _algo_of(call, baseline) == ALGO


# 14. field storage: literal preserved, no guessing ------------------------------

def test_14_field_storage_preserves_literal_without_guessing():
    baseline_src = 'encrypt("AES-256-GCM")\n'
    field_src = ('class C:\n'
                 '    def __init__(self):\n'
                 '        self.algo = "AES-256-GCM"\n'
                 '    def run(self):\n'
                 '        encrypt(self.algo)\n')
    base_facts = F.extract_facts_python(baseline_src, "m.py")
    field_facts = F.extract_facts_python(field_src, "m.py")

    def _literals(facts: list[F.SourceFact]) -> set:
        return {f.value for f in facts if f.kind == "string_literal"
                and isinstance(f.value, str) and f.value}

    assert ALGO in _literals(base_facts)
    assert _literals(field_facts) == _literals(base_facts)
    field_calls = [f for f in field_facts if f.kind == "function_call"
                   and f.name == "encrypt"]
    assert len(field_calls) == 1
    # Attribute indirection is ungrounded: None, not a guess.
    assert _algo_of(field_calls[0], field_facts) is None

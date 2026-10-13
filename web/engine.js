/* General engine: a port of collusion.py's least fixpoint over any scanned setup. */
const Engine = (() => {
  const globRe = p => new RegExp('^' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
  function load(d) {
    if (!d || typeof d !== 'object' || !d.agents || !d.resources) throw new Error('This does not look like scanner output: it needs "agents" and "resources".');
    const resNames = Object.keys(d.resources);
    const match = pats => { const out = new Set(); (pats || []).forEach(p => { const re = globRe(String(p)); resNames.forEach(r => { if (re.test(r)) out.add(r); }); }); return out; };
    const agents = Object.entries(d.agents).map(([id, a]) => ({
      id, title: a.title || id, ai: a.injectable !== false, notes: a.notes || [],
      trusted: !!a.trusted, strips: new Set(a.strips || []),
      r: match(a.read), w: match(a.write),
      flows: (a.flows || []).map(([s, t]) => [match([s]), match([t])]),
    }));
    const idx = Object.fromEntries(agents.map((a, i) => [a.id, i]));
    const gates = [];
    Object.entries(d.agents).forEach(([id, a]) => Object.entries(a.ask || {}).forEach(([g, rt]) =>
      gates.push({ agent: idx[id], name: g, r: match(rt.read), w: match(rt.write) })));
    const res = {};
    resNames.forEach(r => { const x = d.resources[r] || {}; res[r] = { labels: x.labels || [], untrusted: !!x.untrusted, sink: !!x.sink, controls: (x.controls || []).filter(c => c in idx).map(c => idx[c]) }; });
    let policies = d.policies;
    if (!Array.isArray(policies) || !policies.length) {
      const labels = [...new Set(resNames.flatMap(r => res[r].labels))];
      policies = labels.map(l => ({ name: `${l} stays on this machine`, kind: 'no_flow', label: l }));
    }
    policies = policies.map(p => ({ ...p, targets: p.kind === 'no_flow' ? (p.to ? match(p.to) : new Set(resNames.filter(r => res[r].sink))) : null,
      src: p.sources ? new Set(p.sources) : null, srcKey: p.sources ? [...p.sources].sort().join('|') : '*' }));
    return { agents, gates, res, resNames, policies, idx, generated: d.generated };
  }
  function analyze(m, C, G, agentic, sources) {
    const R = m.agents.map(a => new Set(a.r)), W = m.agents.map(a => new Set(a.w));
    m.gates.forEach((g, j) => { if (G.has(j)) { g.r.forEach(x => R[g.agent].add(x)); g.w.forEach(x => W[g.agent].add(x)); } });
    const cor = new Map();
    m.agents.forEach((a, i) => { if (C.has(i) && !a.trusted) cor.set(i, { why: 'hack' }); });
    const taint = new Map();
    m.resNames.forEach(r => { if (m.res[r].untrusted && (!sources || sources.has(r))) taint.set(r, { why: 'source' }); });
    const lab = {};
    m.resNames.forEach(r => { lab[r] = new Map(m.res[r].labels.map(l => [l, { why: 'origin' }])); });
    let ch = true;
    while (ch) {
      ch = false;
      m.agents.forEach((a, i) => {
        if (cor.has(i) || a.trusted) return;
        for (const r of m.resNames) if (taint.has(r) && m.res[r].controls.includes(i)) { cor.set(i, { why: 'control', res: r }); ch = true; return; }
        if (agentic && a.ai) for (const r of [...R[i]].sort()) if (taint.has(r)) { cor.set(i, { why: 'inject', res: r }); ch = true; return; }
      });
      m.agents.forEach((a, i) => {
        if (cor.has(i)) return;
        for (const [sp, dp] of a.flows) for (const s of sp) { if (!R[i].has(s)) continue; for (const d of dp) { if (!W[i].has(d)) continue;
          if (taint.has(s) && !taint.has(d) && !a.strips.has('attacker')) { taint.set(d, { why: 'relay', agent: i, from: s }); ch = true; }
          for (const l of lab[s].keys()) if (!lab[d].has(l) && !a.strips.has(l)) { lab[d].set(l, { why: 'copy', agent: i, from: s, honest: true }); ch = true; } } }
      });
      for (const i of cor.keys()) {
        for (const w of W[i]) if (!taint.has(w)) { taint.set(w, { why: 'written', agent: i }); ch = true; }
        for (const r of R[i]) for (const l of lab[r].keys()) for (const w of W[i])
          if (!lab[w].has(l)) { lab[w].set(l, { why: 'copy', agent: i, from: r }); ch = true; }
      }
    }
    return { cor, taint, lab, R };
  }
  function violated(m, p, res) {
    if (p.kind === 'no_flow') { for (const t of [...p.targets].sort()) if (res.lab[t] && res.lab[t].has(p.label)) return t; }
    else if (p.kind === 'integrity') { if (res.taint.has(p.resource)) return p.resource; }
    else if (p.kind === 'hijack') { const i = m.idx[p.agent]; if (res.cor.has(i)) return p.agent; }
    else if (p.kind === 'learn') { const i = m.idx[p.agent]; for (const r of [...res.R[i]].sort()) if (res.lab[r].has(p.label)) return r; }
    return null;
  }
  /* All k-element subsets of arr, generated lazily in lexicographic order. */
  function* subsets(arr, k) {
    if (k > arr.length) return;
    const idx = Array.from({ length: k }, (_, i) => i);
    while (true) {
      yield idx.map(i => arr[i]);
      let i = k - 1;
      while (i >= 0 && idx[i] === arr.length - k + i) i--;
      if (i < 0) return;
      idx[i]++;
      for (let j = i + 1; j < k; j++) idx[j] = idx[j - 1] + 1;
    }
  }
  /* Pareto frontier of (agents hacked, approvals) for every policy, by
     exhaustive search in order of total cost, within a work limit. complete
     means every combination was tried; otherwise every combination of total
     cost <= searched was. */
  function search(m, agentic, limit = { checks: 150000, ms: 4000 }) {
    const hackable = m.agents.map((a, i) => a.trusted ? -1 : i).filter(i => i >= 0);
    const gateIdx = m.gates.map((_, j) => j);
    const n = hackable.length, g = gateIdx.length;
    const front = m.policies.map(() => []);
    const t0 = Date.now();
    let checks = 0, searched = -1, stopped = false;
    for (let k = 0; k <= n + g && !stopped; k++) {
      for (let t = 0; t <= Math.min(k, n) && !stopped; t++) {
        const h = k - t;
        if (h > g) continue;
        if (m.policies.every((_, q) => front[q].some(p => p.t <= t && p.h <= h))) continue;
        for (const cs of subsets(hackable, t)) {
          if (stopped) break;
          for (const gs of subsets(gateIdx, h)) {
            if (++checks > limit.checks || (checks % 512 === 0 && Date.now() - t0 > limit.ms)) { stopped = true; break; }
            const todo = m.policies.map((_, q) => !front[q].some(p => p.t <= t && p.h <= h));
            if (!todo.some(Boolean)) break;
            const C = new Set(cs), G = new Set(gs), cache = {};
            m.policies.forEach((p, q) => {
              if (!todo[q]) return;
              const res = cache[p.srcKey] || (cache[p.srcKey] = analyze(m, C, G, agentic, p.src));
              const tg = violated(m, p, res); if (tg) front[q].push({ t, h, C, G, res, target: tg });
            });
          }
        }
      }
      if (!stopped) searched = k;
      if (m.policies.every((_, q) => front[q].some(p => p.t === 0 && p.h === 0))) { searched = n + g; break; }
    }
    front.forEach(f => f.sort((a, b) => a.t - b.t || a.h - b.h));
    return { front, complete: searched >= n + g, searched, checks };
  }

  /* Certificate for a rule that holds: one inductive invariant (the least
     fixpoint) per worst case, i.e. per choice of exactly min(t, agents)
     hacked agents and min(h, prompts) approvals. verify.py re-checks it. */
  function certificate(d, m, k, t, h) {
    const hackable = m.agents.map((a, i) => a.trusted ? -1 : i).filter(i => i >= 0);
    const n = hackable.length, g = m.gates.length, tt = Math.min(t, n), hh = Math.min(h, g);
    const combos = (N, K) => { const out = []; const rec = (s, acc) => { if (acc.length === K) { out.push(acc.slice()); return; } for (let i = s; i < N; i++) { acc.push(i); rec(i + 1, acc); acc.pop(); } }; rec(0, []); return out; };
    const p = m.policies[k];
    const { targets, src, srcKey, ...rule } = p;
    const choose = (a, b) => { let r = 1; for (let i = 0; i < b; i++) r = r * (a - i) / (i + 1); return Math.round(r); };
    if (choose(n, tt) * choose(g, hh) > 20000) return { tooLarge: true, cases: choose(n, tt) * choose(g, hh) };
    const invariants = [];
    for (const cs0 of combos(n, tt)) for (const gs of combos(g, hh)) {
      const cs = cs0.map(j => hackable[j]);
      const C = new Set(cs), G = new Set(gs);
      const res = analyze(m, C, G, true, p.src);
      if (violated(m, p, res)) return null;
      const labels = {};
      m.resNames.forEach(r => { if (res.lab[r].size) labels[r] = [...res.lab[r].keys()].sort(); });
      invariants.push({ hacked: cs.map(i => m.agents[i].id), approved: gs.map(j => [m.agents[m.gates[j].agent].id, m.gates[j].name]),
        corrupted: [...res.cor.keys()].map(i => m.agents[i].id).sort(), tainted: [...res.taint.keys()].sort(), labels });
    }
    const setup = { agents: {}, resources: d.resources };
    Object.entries(d.agents).forEach(([id, a]) => { setup.agents[id] = { read: a.read || [], write: a.write || [], injectable: a.injectable !== false, ask: a.ask || {}, flows: a.flows || [], trusted: !!a.trusted, strips: a.strips || [] }; });
    return { format: 'sherlock-cert/1', issued: new Date().toISOString(), rule, budget: { agents: t, approvals: h }, setup, invariants };
  }
  return { load, analyze, search, violated, certificate };
})();
if (typeof module !== 'undefined') module.exports = Engine;

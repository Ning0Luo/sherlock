import { atom, read, update } from 'claude-code'
import type { Register } from 'claude-code'

import type { AttackPoint, GuardEvent, Report } from '../types'

const PANE = 'agentwatch'
// Resolved at runtime from the environment, so the plugin is not tied to one machine.
// Set AGENTWATCH_SCANNER to the path of agentwatch.py (see this plugin's README).
let HOME = ''
let SCANNER = ''
let REPORT = ''
// Claude Code's own memory is written by design; flag it, don't block it. Built once HOME is known.
let OWN_WRITABLE: RegExp[] = []
let OWN_WRITABLE_CMD = /(?!)/
const escRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
async function ready($: any): Promise<boolean> {
  if (HOME) return true
  HOME = ((await $.env.get('HOME')) as string) || ''
  if (!HOME) return false
  SCANNER = ((await $.env.get('AGENTWATCH_SCANNER')) as string) || `${HOME}/.agentwatch/agentwatch.py`
  REPORT = `${HOME}/.agentwatch/report.json`
  OWN_WRITABLE = [new RegExp('^' + escRe(HOME) + '/\\.claude/projects/[^/]+/memory(/|$)')]
  OWN_WRITABLE_CMD = new RegExp(escRe(HOME) + '/\\.claude/projects/[^/\\s\'"]+/memory(/|\\s|\'|"|$)')
  return true
}
const WRITEISH = /(>|\btee\b|\bcp\b|\bmv\b|\brm\b|\bln\b|\bchmod\b|\bsed\s+-i|\bperl\s+-p?i|\btruncate\b|\binstall\b|\bpython3?\b|\bnode\b|\bdd\b)/

const report = atom({ plugin: 'agentwatch', key: 'report' } as const, null)
const events = atom({ plugin: 'agentwatch', key: 'events' } as const, [])
const error = atom({ plugin: 'agentwatch', key: 'error' } as const, null)

type Hit = { kind: 'secret' | 'control' | 'shared'; owner: string; pattern: string }

const expand = (p: string) => (p.startsWith('~/') ? HOME + p.slice(1) : p)

function under(path: string, pattern: string): boolean {
  const pat = expand(pattern)
  if (!pat.includes('*')) return path === pat || path.startsWith(pat + '/')
  const re = new RegExp('^' + pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]+') + '(/|$)')
  return re.test(path)
}

function classify(r: Report, path: string): Hit | null {
  for (const p of r.guard.secret_paths) {
    if (under(path, p)) return { kind: 'secret', owner: 'you', pattern: p }
  }
  for (const [agent, pats] of Object.entries(r.guard.control_paths)) {
    for (const p of pats) {
      if (under(path, p)) return { kind: 'control', owner: agent, pattern: p }
    }
  }
  for (const p of r.guard.shell_rc) {
    if (under(path, p)) return { kind: 'control', owner: 'every shell agent', pattern: p }
  }
  for (const name of r.guard.shared_control) {
    if (path.endsWith('/' + name) || path.includes('/' + name + '/')) {
      return { kind: 'shared', owner: 'every agent working in this project', pattern: name }
    }
  }
  return null
}

async function rescan($: any): Promise<Report | null> {
  try {
    const ran = await $.process.run(
      ['/usr/bin/env', 'python3', SCANNER, 'scan', '--json', REPORT, '--quiet'],
      { timeoutMs: 120_000 },
    )
    if (ran.exitCode !== 0) throw new Error(ran.stderr.slice(-300) || `exit ${ran.exitCode}`)
    const r = JSON.parse(await $.fs.read(REPORT)) as Report
    await update($, report, () => r)
    await update($, error, () => null)
    showStatus($, r)
    return r
  } catch (err) {
    await update($, error, () => String(err))
    $.ui.status('agentwatch: scan failed (/agentwatch for details)')
    return null
  }
}

const isFree = (pts: AttackPoint[]) =>
  pts.length > 0 && pts[0].agents_broken === 0 && pts[0].approvals === 0

function cost(pts: AttackPoint[]): string {
  if (pts.length === 0) return 'safe'
  return pts.map(p => `${p.agents_broken}ag+${p.approvals}ap`).join(' / ')
}

function showStatus($: any, r: Report) {
  const all = Object.values(r.attacks)
  const free = all.filter(isFree).length
  const open = all.filter(p => p.length > 0).length
  $.ui.status(
    free > 0
      ? `agentwatch: ${free}/${all.length} policies break with no hack and no approval`
      : open > 0
        ? `agentwatch: ${open}/${all.length} policies breakable (needs hacks or approvals)`
        : `agentwatch: ${r.agents.length} agents, all policies hold`,
  )
}

async function record($: any, ev: Omit<GuardEvent, 'at'>) {
  const at = new Date(await $.clock.now()).toTimeString().slice(0, 8)
  await update($, events, list => [...list, { ...ev, at }].slice(-100))
}

async function allowed($: any, path: string): Promise<boolean> {
  const list = ((await $.store.get('allow')) as string[] | undefined) ?? []
  return list.some(p => under(path, p))
}

async function resolve($: any, path: string): Promise<string[]> {
  const stat = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
  return stat?.realPath && stat.realPath !== path ? [path, stat.realPath] : [path]
}

async function guardPath($: any, tool: string, path: string, isWrite: boolean) {
  const r = await read($, report)
  if (!r || !path) return null
  for (const p of await resolve($, expand(path))) {
    if (await allowed($, p)) return null
    if (OWN_WRITABLE.some(re => re.test(p))) return null
    const hit = classify(r, p)
    if (!hit) continue
    if (hit.kind === 'secret') {
      await record($, { action: 'denied', tool, target: p, why: 'secret store' })
      return {
        deny:
          `agentwatch: ${p} is a secret store (${hit.pattern}). Reading or writing it from an agent ` +
          `puts the secret one injection away from the network. Ask the user; they can run ` +
          `/agentwatch allow ${hit.pattern} to permit it.`,
      }
    }
    if (!isWrite) return null
    if (hit.kind === 'control') {
      await record($, { action: 'denied', tool, target: p, why: `controls ${hit.owner}` })
      return {
        deny:
          `agentwatch: ${p} configures or instructs ${hit.owner}. Writing it hands this agent's ` +
          `influence to that agent (cross-agent escalation). Ask the user first; they can run ` +
          `/agentwatch allow ${hit.pattern}.`,
      }
    }
    await record($, { action: 'flagged', tool, target: p, why: `read by ${hit.owner}` })
    $.ui.toast(`agentwatch: wrote ${p.split('/').pop()}, which other agents read as instructions`)
  }
  return null
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    const ok = await ready($)
    await $.command.register({
      name: 'agentwatch',
      description: 'Agent rights monitor: pane | scan | allow <path> | allowed | forget',
    })
    if (ok) void rescan($)
    return next(e)
  })

  on('command.run', { command: 'agentwatch' }, async ($, e) => {
    await ready($)
    const [sub, ...rest] = e.args.trim().split(/\s+/)
    if (sub === 'scan') {
      const r = await rescan($)
      return { text: r ? 'agentwatch: rescanned.' : `agentwatch: scan failed: ${await read($, error)}` }
    }
    if (sub === 'allow' && rest.length) {
      const list = ((await $.store.get('allow')) as string[] | undefined) ?? []
      await $.store.set('allow', [...new Set([...list, rest.join(' ')])])
      return { text: `agentwatch: allowed ${rest.join(' ')} (kept across sessions; /agentwatch forget clears).` }
    }
    if (sub === 'allowed') {
      const list = ((await $.store.get('allow')) as string[] | undefined) ?? []
      return { text: list.length ? 'Allowed:\n' + list.join('\n') : 'Nothing allowed.' }
    }
    if (sub === 'forget') {
      await $.store.delete('allow')
      return { text: 'agentwatch: allow list cleared.' }
    }
    await $.ui.open({ id: PANE, title: 'Agent rights' })
    return { text: 'agentwatch pane opened.' }
  })

  for (const tool of ['Write', 'Edit', 'NotebookEdit'] as const) {
    on('tool.call', { tool }, async ($, e: any, next) => {
      if (!(await ready($))) return next(e)
      const verdict = await guardPath($, tool, e.file_path ?? e.notebook_path, true)
      if (verdict) return verdict
      return next(e)
    })
  }

  on('tool.call', { tool: 'Read' }, async ($, e, next) => {
    if (!(await ready($))) return next(e)
    const verdict = await guardPath($, 'Read', e.file_path, false)
    return verdict ?? next(e)
  })

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    if (!(await ready($))) return next(e)
    const r = await read($, report)
    if (!r) return next(e)
    const cmd = e.command.replace(/\$\{?HOME\}?/g, HOME).replace(/(^|[\s'"=:])~\//g, `$1${HOME}/`)
    for (const p of r.guard.secret_paths) {
      if (cmd.includes(p) && !(await allowed($, p))) {
        await record($, { action: 'denied', tool: 'Bash', target: p, why: 'secret store' })
        return {
          deny: `agentwatch: this command touches the secret store ${p}. Ask the user; they can run /agentwatch allow ${p}.`,
        }
      }
    }
    if (WRITEISH.test(cmd)) {
      const pats = [...Object.values(r.guard.control_paths).flat(), ...r.guard.shell_rc]
      for (const pat of pats) {
        const p = expand(pat).split('*')[0].replace(/\/$/, '')
        const onlyMemory = pat.endsWith('/memory') && OWN_WRITABLE_CMD.test(cmd)
          && cmd.split(p).length - 1 === (cmd.match(new RegExp(OWN_WRITABLE_CMD.source, 'g')) ?? []).length
        if (p.length > HOME.length + 2 && cmd.includes(p) && !onlyMemory
            && !(await allowed($, p))) {
          await record($, { action: 'denied', tool: 'Bash', target: p, why: 'agent control file' })
          return {
            deny: `agentwatch: this command may modify ${p}, which configures an agent. Ask the user; they can run /agentwatch allow ${pat}.`,
          }
        }
      }
    }
    return next(e)
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    await ready($)
    const { Box, Text } = $.ui.resolve(e)
    const r = await read($, report)
    const evs = await read($, events)
    const err = await read($, error)
    if (!r) return <Text dimColor>{err ? `Scan failed: ${err}` : 'Scanning agents...'}</Text>
    const row = ([name, pts]: [string, AttackPoint[]]) => (
      <Text color={pts.length === 0 ? 'green' : isFree(pts) ? 'red' : 'yellow'}>
        {cost(pts).padEnd(14)} {name}
      </Text>
    )
    return (
      <Box flexDirection="column">
        <Text bold>Agents ({r.agents.length}), scanned {r.generated}</Text>
        {r.agents.map(a => <Text>  {a.title}</Text>)}
        <Text> </Text>
        <Text bold>Cheapest attacks now (ag = agents hacked, ap = approvals you give)</Text>
        {Object.entries(r.attacks).map(row)}
        {r.plan.map(st => (
          <Box flexDirection="column">
            <Text> </Text>
            <Text bold>{st.label}</Text>
            {Object.entries(st.attacks).map(row)}
          </Box>
        ))}
        <Text> </Text>
        <Text bold>Guard events this session ({evs.length})</Text>
        {evs.length === 0 && <Text dimColor>  none</Text>}
        {evs.slice(-10).map(ev => (
          <Text color={ev.action === 'denied' ? 'red' : 'yellow'}>
            {ev.at} {ev.action} {ev.tool} {ev.target.replace(HOME, '~')} ({ev.why})
          </Text>
        ))}
      </Box>
    )
  })
}

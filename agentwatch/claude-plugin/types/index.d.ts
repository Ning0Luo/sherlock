export type AttackPoint = {
  agents_broken: number
  approvals: number
  broken: string[]
  approved: string[]
  path: string[] | null
}
export type Stage = { label: string; steps: string[]; attacks: Record<string, AttackPoint[]> }
export type Report = {
  generated: string
  agents: { name: string; title: string; notes: string[]; control_paths: string[] }[]
  attacks: Record<string, AttackPoint[]>
  plan: Stage[]
  guard: {
    secret_paths: string[]
    control_paths: Record<string, string[]>
    shared_control: string[]
    shell_rc: string[]
  }
}
export type GuardEvent = { at: string; action: 'denied' | 'flagged'; tool: string; target: string; why: string }

declare module 'claude-code' {
  interface PluginState {
    agentwatch: { report: Report | null; events: GuardEvent[]; error: string | null }
  }
}

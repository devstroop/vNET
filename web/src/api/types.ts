export type Counters = {
  forwarded: number
  bridged: number
  dropped: number
  firewall_dropped: number
  pending_queued: number
  pending_flushed: number
  conntrack_created: number
  conntrack_removed: number
  conntrack_hits: number
  conntrack_misses: number
  conntrack_table_full: number
  snat_packets: number
  dnat_packets: number
  icmp_translated: number
  dhcp_offers: number
  dhcp_acks: number
  dhcp_requests: number
  dhcp_client_bound: number
  storm_dropped: number
  stp_bpdus_rx: number
  stp_bpdus_tx: number
  stp_filtered: number
  stp_invalid: number
  ipv6_forwarded: number
  ipv6_local_delivered: number
  ipv6_dropped: number
  ndp_requests: number
  ndp_advertisements: number
  ndp_learned: number
  ndp_rate_limited: number
  ndp_dropped: number
  icmpv6_errors: number
  icmpv6_echoes: number
}

export type Status = {
  instance: string
  version: string
  pid: number
  started_ms: number
  updated_ms: number
  uptime_ms: number
  state_dir: string
  control_path: string
  ports: number
  counters: Counters
}

export type Snat = {
  out: string
  addr: string
}

export type PortForward = {
  proto: string
  ext_port: number
  to_addr: string
  to_port: number
  ingress?: string | null
}

export type Nat = {
  instance: string
  snat: Snat[]
  port_forward: PortForward[]
}

export type ConntrackEntry = {
  proto: string
  state: string
  src: string
  sport: number
  dst: string
  dport: number
  translated_src?: string | null
  translated_sport: number
  translated_dst?: string | null
  translated_dport: number
  packets: number
  bytes: number
  reply_packets: number
  reply_bytes: number
  created_ms: number
  last_seen_ms: number
  timeout_ms: number
}

export type Conntrack = {
  instance: string
  total: number
  returned: number
  entries: ConntrackEntry[]
}

export type Session = {
  authenticated: boolean
  csrf?: string
}

export type LoginResponse = {
  ok: boolean
  csrf?: string
  code?: string
  message?: string
}

export type StatusResponse = {
  ok: boolean
  status: Status
}

export type NatResponse = {
  ok: boolean
  nat: Nat
}

export type ConntrackResponse = {
  ok: boolean
  conntrack: Conntrack
}

export type ApiErrorBody = {
  ok?: boolean
  code?: string
  message?: string
}

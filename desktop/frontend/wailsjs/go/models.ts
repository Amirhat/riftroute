export namespace domain {
	
	export class ManagedRule {
	    priority: number;
	    selector: string;
	    table: string;
	    family: string;
	    proto?: string;
	    profile_id: string;
	    // Go type: time
	    created_at: any;
	
	    static createFrom(source: any = {}) {
	        return new ManagedRule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.priority = source["priority"];
	        this.selector = source["selector"];
	        this.table = source["table"];
	        this.family = source["family"];
	        this.proto = source["proto"];
	        this.profile_id = source["profile_id"];
	        this.created_at = this.convertValues(source["created_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ManagedRoute {
	    dst_cidr: string;
	    gateway?: string;
	    iface: string;
	    metric: number;
	    family: string;
	    owner: string;
	    proto?: string;
	    table?: string;
	    profile?: string;
	    profile_id: string;
	    // Go type: time
	    created_at: any;
	
	    static createFrom(source: any = {}) {
	        return new ManagedRoute(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dst_cidr = source["dst_cidr"];
	        this.gateway = source["gateway"];
	        this.iface = source["iface"];
	        this.metric = source["metric"];
	        this.family = source["family"];
	        this.owner = source["owner"];
	        this.proto = source["proto"];
	        this.table = source["table"];
	        this.profile = source["profile"];
	        this.profile_id = source["profile_id"];
	        this.created_at = this.convertValues(source["created_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PlanOp {
	    kind: string;
	    route?: ManagedRoute;
	    rule?: ManagedRule;
	    command: string[];
	    human: string;
	
	    static createFrom(source: any = {}) {
	        return new PlanOp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.route = this.convertValues(source["route"], ManagedRoute);
	        this.rule = this.convertValues(source["rule"], ManagedRule);
	        this.command = source["command"];
	        this.human = source["human"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Plan {
	    ops: PlanOp[];
	    inverse: PlanOp[];
	
	    static createFrom(source: any = {}) {
	        return new Plan(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ops = this.convertValues(source["ops"], PlanOp);
	        this.inverse = this.convertValues(source["inverse"], PlanOp);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AuditEvent {
	    id: number;
	    // Go type: time
	    ts: any;
	    actor: string;
	    action: string;
	    profile?: string;
	    plan?: Plan;
	    result: string;
	    rollback?: boolean;
	    reason?: string;
	
	    static createFrom(source: any = {}) {
	        return new AuditEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.ts = this.convertValues(source["ts"], null);
	        this.actor = source["actor"];
	        this.action = source["action"];
	        this.profile = source["profile"];
	        this.plan = this.convertValues(source["plan"], Plan);
	        this.result = source["result"];
	        this.rollback = source["rollback"];
	        this.reason = source["reason"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Capabilities {
	    platform: string;
	    policy_routing: boolean;
	    fwmark: boolean;
	    per_app_routing: boolean;
	    proto_tag: boolean;
	    ipv6: boolean;
	    kill_switch: boolean;
	    iface_scoping: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Capabilities(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.platform = source["platform"];
	        this.policy_routing = source["policy_routing"];
	        this.fwmark = source["fwmark"];
	        this.per_app_routing = source["per_app_routing"];
	        this.proto_tag = source["proto_tag"];
	        this.ipv6 = source["ipv6"];
	        this.kill_switch = source["kill_switch"];
	        this.iface_scoping = source["iface_scoping"];
	    }
	}
	export class DNSState {
	    servers: string[];
	    search_domains?: string[];
	    iface?: string;
	
	    static createFrom(source: any = {}) {
	        return new DNSState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.servers = source["servers"];
	        this.search_domains = source["search_domains"];
	        this.iface = source["iface"];
	    }
	}
	export class DefaultRoute {
	    family: string;
	    present: boolean;
	    gateway?: string;
	    iface?: string;
	    owner: string;
	    via_vpn: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DefaultRoute(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.family = source["family"];
	        this.present = source["present"];
	        this.gateway = source["gateway"];
	        this.iface = source["iface"];
	        this.owner = source["owner"];
	        this.via_vpn = source["via_vpn"];
	    }
	}
	export class Route {
	    dst_cidr: string;
	    gateway?: string;
	    iface: string;
	    metric: number;
	    family: string;
	    owner: string;
	    proto?: string;
	    table?: string;
	    profile?: string;
	
	    static createFrom(source: any = {}) {
	        return new Route(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dst_cidr = source["dst_cidr"];
	        this.gateway = source["gateway"];
	        this.iface = source["iface"];
	        this.metric = source["metric"];
	        this.family = source["family"];
	        this.owner = source["owner"];
	        this.proto = source["proto"];
	        this.table = source["table"];
	        this.profile = source["profile"];
	    }
	}
	export class DiffEntry {
	    action: string;
	    route: Route;
	
	    static createFrom(source: any = {}) {
	        return new DiffEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.action = source["action"];
	        this.route = this.convertValues(source["route"], Route);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Diff {
	    entries: DiffEntry[];
	    adds: number;
	    dels: number;
	    changes: number;
	    in_sync: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Diff(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.entries = this.convertValues(source["entries"], DiffEntry);
	        this.adds = source["adds"];
	        this.dels = source["dels"];
	        this.changes = source["changes"];
	        this.in_sync = source["in_sync"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class DoctorCheck {
	    name: string;
	    status: string;
	    detail: string;
	    fix?: string;
	
	    static createFrom(source: any = {}) {
	        return new DoctorCheck(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.status = source["status"];
	        this.detail = source["detail"];
	        this.fix = source["fix"];
	    }
	}
	export class DoctorReport {
	    checks: DoctorCheck[];
	    pass: number;
	    warn: number;
	    fail: number;
	    ok: boolean;
	    // Go type: time
	    generated_at: any;
	
	    static createFrom(source: any = {}) {
	        return new DoctorReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.checks = this.convertValues(source["checks"], DoctorCheck);
	        this.pass = source["pass"];
	        this.warn = source["warn"];
	        this.fail = source["fail"];
	        this.ok = source["ok"];
	        this.generated_at = this.convertValues(source["generated_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DriftStatus {
	    pending: boolean;
	    adds: number;
	    dels: number;
	    changes: number;
	
	    static createFrom(source: any = {}) {
	        return new DriftStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pending = source["pending"];
	        this.adds = source["adds"];
	        this.dels = source["dels"];
	        this.changes = source["changes"];
	    }
	}
	export class Health {
	    daemon: string;
	    reason?: string;
	    version: string;
	    provider: string;
	    uptime_seconds: number;
	    pid: number;
	
	    static createFrom(source: any = {}) {
	        return new Health(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.daemon = source["daemon"];
	        this.reason = source["reason"];
	        this.version = source["version"];
	        this.provider = source["provider"];
	        this.uptime_seconds = source["uptime_seconds"];
	        this.pid = source["pid"];
	    }
	}
	export class Iface {
	    name: string;
	    up: boolean;
	    kind: string;
	    addrs: string[];
	    mtu?: number;
	    is_vpn: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Iface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.up = source["up"];
	        this.kind = source["kind"];
	        this.addrs = source["addrs"];
	        this.mtu = source["mtu"];
	        this.is_vpn = source["is_vpn"];
	    }
	}
	export class Leak {
	    kind: string;
	    severity: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new Leak(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.severity = source["severity"];
	        this.detail = source["detail"];
	    }
	}
	
	
	
	
	export class PolicyRule {
	    priority: number;
	    selector: string;
	    table: string;
	    family: string;
	    proto?: string;
	
	    static createFrom(source: any = {}) {
	        return new PolicyRule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.priority = source["priority"];
	        this.selector = source["selector"];
	        this.table = source["table"];
	        this.family = source["family"];
	        this.proto = source["proto"];
	    }
	}
	export class Rule {
	    type: string;
	    value: string;
	    comment?: string;
	
	    static createFrom(source: any = {}) {
	        return new Rule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.value = source["value"];
	        this.comment = source["comment"];
	    }
	}
	export class Profile {
	    id: string;
	    name: string;
	    enabled: boolean;
	    mode: string;
	    gateway: string;
	    priority: number;
	    rules: Rule[];
	    lists: string[];
	    ip_version?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Profile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.enabled = source["enabled"];
	        this.mode = source["mode"];
	        this.gateway = source["gateway"];
	        this.priority = source["priority"];
	        this.rules = this.convertValues(source["rules"], Rule);
	        this.lists = source["lists"];
	        this.ip_version = source["ip_version"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ProfileStatus {
	    id: string;
	    name: string;
	    enabled: boolean;
	    mode: string;
	    rule_count: number;
	    applied: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProfileStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.enabled = source["enabled"];
	        this.mode = source["mode"];
	        this.rule_count = source["rule_count"];
	        this.applied = source["applied"];
	    }
	}
	
	export class RouteDecision {
	    target: string;
	    source: string;
	    matched_cidr?: string;
	    gateway?: string;
	    iface: string;
	    family: string;
	    owner?: string;
	    profile?: string;
	    via_vpn: boolean;
	    reachable: boolean;
	
	    static createFrom(source: any = {}) {
	        return new RouteDecision(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.source = source["source"];
	        this.matched_cidr = source["matched_cidr"];
	        this.gateway = source["gateway"];
	        this.iface = source["iface"];
	        this.family = source["family"];
	        this.owner = source["owner"];
	        this.profile = source["profile"];
	        this.via_vpn = source["via_vpn"];
	        this.reachable = source["reachable"];
	    }
	}
	export class RouteExplain {
	    target: string;
	    resolved?: string[];
	    kernel: RouteDecision;
	    simulated?: RouteDecision;
	    drift: boolean;
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new RouteExplain(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.resolved = source["resolved"];
	        this.kernel = this.convertValues(source["kernel"], RouteDecision);
	        this.simulated = this.convertValues(source["simulated"], RouteDecision);
	        this.drift = source["drift"];
	        this.note = source["note"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Snapshot {
	    id: string;
	    // Go type: time
	    created_at: any;
	    reason: string;
	    routes_v4: Route[];
	    routes_v6: Route[];
	    rules?: PolicyRule[];
	    defaults: DefaultRoute[];
	    dns: DNSState;
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.reason = source["reason"];
	        this.routes_v4 = this.convertValues(source["routes_v4"], Route);
	        this.routes_v6 = this.convertValues(source["routes_v6"], Route);
	        this.rules = this.convertValues(source["rules"], PolicyRule);
	        this.defaults = this.convertValues(source["defaults"], DefaultRoute);
	        this.dns = this.convertValues(source["dns"], DNSState);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class VPNStatus {
	    active: boolean;
	    interfaces: string[];
	
	    static createFrom(source: any = {}) {
	        return new VPNStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.active = source["active"];
	        this.interfaces = source["interfaces"];
	    }
	}
	export class State {
	    health: Health;
	    capabilities: Capabilities;
	    vpn: VPNStatus;
	    interfaces: Iface[];
	    defaults: DefaultRoute[];
	    dns: DNSState;
	    profiles: ProfileStatus[];
	    drift: DriftStatus;
	    managed_route_count: number;
	    auto_apply: boolean;
	    kill_switch: boolean;
	    // Go type: time
	    generated_at: any;
	
	    static createFrom(source: any = {}) {
	        return new State(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.health = this.convertValues(source["health"], Health);
	        this.capabilities = this.convertValues(source["capabilities"], Capabilities);
	        this.vpn = this.convertValues(source["vpn"], VPNStatus);
	        this.interfaces = this.convertValues(source["interfaces"], Iface);
	        this.defaults = this.convertValues(source["defaults"], DefaultRoute);
	        this.dns = this.convertValues(source["dns"], DNSState);
	        this.profiles = this.convertValues(source["profiles"], ProfileStatus);
	        this.drift = this.convertValues(source["drift"], DriftStatus);
	        this.managed_route_count = source["managed_route_count"];
	        this.auto_apply = source["auto_apply"];
	        this.kill_switch = source["kill_switch"];
	        this.generated_at = this.convertValues(source["generated_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class DaemonInfo {
	    manager: string;
	    installed: boolean;
	    loaded: boolean;
	    reachable: boolean;
	    version?: string;
	    can_manage: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DaemonInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.manager = source["manager"];
	        this.installed = source["installed"];
	        this.loaded = source["loaded"];
	        this.reachable = source["reachable"];
	        this.version = source["version"];
	        this.can_manage = source["can_manage"];
	    }
	}

}

export namespace safety {
	
	export class Violation {
	    rule: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new Violation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rule = source["rule"];
	        this.detail = source["detail"];
	    }
	}
	export class Result {
	    tx_id?: string;
	    plan: domain.Plan;
	    diff: domain.Diff;
	    violations?: Violation[];
	    status: string;
	    needs_confirm: boolean;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tx_id = source["tx_id"];
	        this.plan = this.convertValues(source["plan"], domain.Plan);
	        this.diff = this.convertValues(source["diff"], domain.Diff);
	        this.violations = this.convertValues(source["violations"], Violation);
	        this.status = source["status"];
	        this.needs_confirm = source["needs_confirm"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}


export namespace main {

	export class SecurityFinding {
	    id: string;
	    severity: string;
	    title: string;
	    description: string;
	    recommendation: string;
	    evidence?: string;

	    static createFrom(source: any = {}) {
	        return new SecurityFinding(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.severity = source["severity"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.recommendation = source["recommendation"];
	        this.evidence = source["evidence"];
	    }
	}
	export class TLSDetails {
	    version: string;
	    cipherSuite: string;
	    subject: string;
	    issuer: string;
	    // Go type: time
	    expiresAt: any;
	    daysRemaining: number;
	    verified: boolean;

	    static createFrom(source: any = {}) {
	        return new TLSDetails(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.cipherSuite = source["cipherSuite"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.expiresAt = this.convertValues(source["expiresAt"], null);
	        this.daysRemaining = source["daysRemaining"];
	        this.verified = source["verified"];
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
	export class BulkHeaderResult {
	    url: string;
	    finalUrl: string;
	    statusCode: number;
	    title: string;
	    server: string;
	    poweredBy: string;
	    technologies: string[];
	    edgeServices: string[];
	    grade: string;
	    riskScore: number;
	    missing: string[];
	    present: Record<string, string>;
	    tls?: TLSDetails;
	    findings: SecurityFinding[];
	    error: string;

	    static createFrom(source: any = {}) {
	        return new BulkHeaderResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.finalUrl = source["finalUrl"];
	        this.statusCode = source["statusCode"];
	        this.title = source["title"];
	        this.server = source["server"];
	        this.poweredBy = source["poweredBy"];
	        this.technologies = source["technologies"];
	        this.edgeServices = source["edgeServices"];
	        this.grade = source["grade"];
	        this.riskScore = source["riskScore"];
	        this.missing = source["missing"];
	        this.present = source["present"];
	        this.tls = this.convertValues(source["tls"], TLSDetails);
	        this.findings = this.convertValues(source["findings"], SecurityFinding);
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
	export class RDAPInfo {
	    ip: string;
	    networkHandle?: string;
	    country?: string;
	    name?: string;

	    static createFrom(source: any = {}) {
	        return new RDAPInfo(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.networkHandle = source["networkHandle"];
	        this.country = source["country"];
	        this.name = source["name"];
	    }
	}
	export class DNSIntelligenceResult {
	    domain: string;
	    a: string[];
	    aaaa: string[];
	    mx: string[];
	    ns: string[];
	    txt: string[];
	    spf: string[];
	    dmarc: string[];
	    ptr: Record<string, Array<string>>;
	    rdap?: RDAPInfo[];
	    errors?: string[];

	    static createFrom(source: any = {}) {
	        return new DNSIntelligenceResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.a = source["a"];
	        this.aaaa = source["aaaa"];
	        this.mx = source["mx"];
	        this.ns = source["ns"];
	        this.txt = source["txt"];
	        this.spf = source["spf"];
	        this.dmarc = source["dmarc"];
	        this.ptr = source["ptr"];
	        this.rdap = this.convertValues(source["rdap"], RDAPInfo);
	        this.errors = source["errors"];
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
	export class HistoryEntry {
	    id: number;
	    scanType: string;
	    target: string;
	    result: string;
	    // Go type: time
	    createdAt: any;

	    static createFrom(source: any = {}) {
	        return new HistoryEntry(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.scanType = source["scanType"];
	        this.target = source["target"];
	        this.result = source["result"];
	        this.createdAt = this.convertValues(source["createdAt"], null);
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
	export class PathFinding {
	    url: string;
	    statusCode: number;
	    contentLength: number;

	    static createFrom(source: any = {}) {
	        return new PathFinding(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.statusCode = source["statusCode"];
	        this.contentLength = source["contentLength"];
	    }
	}
	export class PathFuzzResult {
	    baseUrl: string;
	    paths: PathFinding[];
	    error?: string;

	    static createFrom(source: any = {}) {
	        return new PathFuzzResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.baseUrl = source["baseUrl"];
	        this.paths = this.convertValues(source["paths"], PathFinding);
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
	export class PortFinding {
	    port: number;
	    service: string;
	    banner: string;

	    static createFrom(source: any = {}) {
	        return new PortFinding(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.service = source["service"];
	        this.banner = source["banner"];
	    }
	}
	export class PortScanDiff {
	    target: string;
	    // Go type: time
	    latestAt?: any;
	    // Go type: time
	    previousAt?: any;
	    newPorts: number[];
	    removedPorts: number[];

	    static createFrom(source: any = {}) {
	        return new PortScanDiff(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.latestAt = this.convertValues(source["latestAt"], null);
	        this.previousAt = this.convertValues(source["previousAt"], null);
	        this.newPorts = source["newPorts"];
	        this.removedPorts = source["removedPorts"];
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


	export class SubdomainResult {
	    domain: string;
	    names: string[];
	    errors?: string[];

	    static createFrom(source: any = {}) {
	        return new SubdomainResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.names = source["names"];
	        this.errors = source["errors"];
	    }
	}

	export class TLSInspection {
	    host: string;
	    port: string;
	    subject: string;
	    issuer: string;
	    // Go type: time
	    notBefore: any;
	    // Go type: time
	    notAfter: any;
	    daysRemaining: number;
	    sans: string[];
	    selfSigned: boolean;
	    trusted: boolean;
	    validationError?: string;
	    tlsVersion: string;
	    cipherSuite: string;
	    tls10Accepted: boolean;
	    tls11Accepted: boolean;
	    tls10Error?: string;
	    tls11Error?: string;

	    static createFrom(source: any = {}) {
	        return new TLSInspection(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.notBefore = this.convertValues(source["notBefore"], null);
	        this.notAfter = this.convertValues(source["notAfter"], null);
	        this.daysRemaining = source["daysRemaining"];
	        this.sans = source["sans"];
	        this.selfSigned = source["selfSigned"];
	        this.trusted = source["trusted"];
	        this.validationError = source["validationError"];
	        this.tlsVersion = source["tlsVersion"];
	        this.cipherSuite = source["cipherSuite"];
	        this.tls10Accepted = source["tls10Accepted"];
	        this.tls11Accepted = source["tls11Accepted"];
	        this.tls10Error = source["tls10Error"];
	        this.tls11Error = source["tls11Error"];
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


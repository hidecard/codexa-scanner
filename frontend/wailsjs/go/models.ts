export namespace main {
	
	export class AdvisoryCVE {
	    cve: string;
	    title: string;
	    affectedVersions: string;
	    fixedVersion: string;
	    severity: string;
	    description: string;
	    references: string[];
	
	    static createFrom(source: any = {}) {
	        return new AdvisoryCVE(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cve = source["cve"];
	        this.title = source["title"];
	        this.affectedVersions = source["affectedVersions"];
	        this.fixedVersion = source["fixedVersion"];
	        this.severity = source["severity"];
	        this.description = source["description"];
	        this.references = source["references"];
	    }
	}
	export class AdvisoryMatch {
	    product: string;
	    detectedVersion?: string;
	    matches: AdvisoryCVE[];
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new AdvisoryMatch(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.product = source["product"];
	        this.detectedVersion = source["detectedVersion"];
	        this.matches = this.convertValues(source["matches"], AdvisoryCVE);
	        this.source = source["source"];
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
	export class Alignment {
	    spf?: string;
	    dkim?: string;
	
	    static createFrom(source: any = {}) {
	        return new Alignment(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.spf = source["spf"];
	        this.dkim = source["dkim"];
	    }
	}
	export class BilingualText {
	    en: string;
	    my: string;
	
	    static createFrom(source: any = {}) {
	        return new BilingualText(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.en = source["en"];
	        this.my = source["my"];
	    }
	}
	export class BilingualTextList {
	    en: string[];
	    my: string[];
	
	    static createFrom(source: any = {}) {
	        return new BilingualTextList(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.en = source["en"];
	        this.my = source["my"];
	    }
	}
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
	export class ClientSideClue {
	    kind: string;
	    value?: string;
	    context?: string;
	    scriptUrl?: string;
	    line?: number;
	    note?: string;
	    reachable?: boolean;
	    statusCode?: number;
	
	    static createFrom(source: any = {}) {
	        return new ClientSideClue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.value = source["value"];
	        this.context = source["context"];
	        this.scriptUrl = source["scriptUrl"];
	        this.line = source["line"];
	        this.note = source["note"];
	        this.reachable = source["reachable"];
	        this.statusCode = source["statusCode"];
	    }
	}
	export class ClientSideAudit {
	    scriptsFetched: number;
	    scriptsScanned: number;
	    truncated?: boolean;
	    secretFindings?: ClientSideClue[];
	    sourceMapClues?: ClientSideClue[];
	    endpointClues?: ClientSideClue[];
	    domSinks?: ClientSideClue[];
	    reflectedParamProbe?: ClientSideClue;
	    notes?: string[];
	
	    static createFrom(source: any = {}) {
	        return new ClientSideAudit(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.scriptsFetched = source["scriptsFetched"];
	        this.scriptsScanned = source["scriptsScanned"];
	        this.truncated = source["truncated"];
	        this.secretFindings = this.convertValues(source["secretFindings"], ClientSideClue);
	        this.sourceMapClues = this.convertValues(source["sourceMapClues"], ClientSideClue);
	        this.endpointClues = this.convertValues(source["endpointClues"], ClientSideClue);
	        this.domSinks = this.convertValues(source["domSinks"], ClientSideClue);
	        this.reflectedParamProbe = this.convertValues(source["reflectedParamProbe"], ClientSideClue);
	        this.notes = source["notes"];
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
	export class WebResourceInspector {
	    url: string;
	    statusCode: number;
	    found: boolean;
	    body?: string;
	    error?: string;
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new WebResourceInspector(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.statusCode = source["statusCode"];
	        this.found = source["found"];
	        this.body = source["body"];
	        this.error = source["error"];
	        this.note = source["note"];
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
	    verificationSummary?: string;
	    chainSubjects?: string[];
	    // Go type: time
	    notBefore?: any;
	    sanCount?: number;
	
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
	        this.verificationSummary = source["verificationSummary"];
	        this.chainSubjects = source["chainSubjects"];
	        this.notBefore = this.convertValues(source["notBefore"], null);
	        this.sanCount = source["sanCount"];
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
	export class RedirectHop {
	    from: string;
	    to: string;
	    statusCode: number;
	
	    static createFrom(source: any = {}) {
	        return new RedirectHop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = source["from"];
	        this.to = source["to"];
	        this.statusCode = source["statusCode"];
	    }
	}
	export class BulkHeaderResult {
	    url: string;
	    finalUrl: string;
	    assessment?: string;
	    redirects?: RedirectHop[];
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
	    securityTxt?: WebResourceInspector;
	    robotsTxt?: WebResourceInspector;
	    clientSideAudit?: ClientSideAudit;
	    findings: SecurityFinding[];
	    advisoryMatches?: AdvisoryMatch[];
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new BulkHeaderResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.finalUrl = source["finalUrl"];
	        this.assessment = source["assessment"];
	        this.redirects = this.convertValues(source["redirects"], RedirectHop);
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
	        this.securityTxt = this.convertValues(source["securityTxt"], WebResourceInspector);
	        this.robotsTxt = this.convertValues(source["robotsTxt"], WebResourceInspector);
	        this.clientSideAudit = this.convertValues(source["clientSideAudit"], ClientSideAudit);
	        this.findings = this.convertValues(source["findings"], SecurityFinding);
	        this.advisoryMatches = this.convertValues(source["advisoryMatches"], AdvisoryMatch);
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
	
	
	export class DKIMAnalysis {
	    recordsFound: number;
	    selectors?: string[];
	    keyTypes?: string[];
	    keySizes?: number[];
	    warnings?: string[];
	
	    static createFrom(source: any = {}) {
	        return new DKIMAnalysis(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.recordsFound = source["recordsFound"];
	        this.selectors = source["selectors"];
	        this.keyTypes = source["keyTypes"];
	        this.keySizes = source["keySizes"];
	        this.warnings = source["warnings"];
	    }
	}
	export class DKIMRecord {
	    selector: string;
	    record: string;
	    keyType?: string;
	    keySize?: number;
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new DKIMRecord(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.selector = source["selector"];
	        this.record = source["record"];
	        this.keyType = source["keyType"];
	        this.keySize = source["keySize"];
	        this.note = source["note"];
	    }
	}
	export class DMARCAnalysis {
	    record: string;
	    hasDMARC: boolean;
	    policy?: string;
	    subdomainPolicy?: string;
	    percent?: number;
	    rua?: string[];
	    ruf?: string[];
	    alignment?: Alignment;
	    warnings?: string[];
	
	    static createFrom(source: any = {}) {
	        return new DMARCAnalysis(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.record = source["record"];
	        this.hasDMARC = source["hasDMARC"];
	        this.policy = source["policy"];
	        this.subdomainPolicy = source["subdomainPolicy"];
	        this.percent = source["percent"];
	        this.rua = source["rua"];
	        this.ruf = source["ruf"];
	        this.alignment = this.convertValues(source["alignment"], Alignment);
	        this.warnings = source["warnings"];
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
	export class SPFAnalysis {
	    record: string;
	    hasSPF: boolean;
	    allMechanism?: string;
	    weakMechanisms?: string[];
	    includes?: string[];
	    redirects?: string[];
	    warnings?: string[];
	
	    static createFrom(source: any = {}) {
	        return new SPFAnalysis(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.record = source["record"];
	        this.hasSPF = source["hasSPF"];
	        this.allMechanism = source["allMechanism"];
	        this.weakMechanisms = source["weakMechanisms"];
	        this.includes = source["includes"];
	        this.redirects = source["redirects"];
	        this.warnings = source["warnings"];
	    }
	}
	export class EmailPolicyAnalysis {
	    spf: SPFAnalysis;
	    dmarc: DMARCAnalysis;
	    dkim: DKIMAnalysis;
	    rating: string;
	
	    static createFrom(source: any = {}) {
	        return new EmailPolicyAnalysis(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.spf = this.convertValues(source["spf"], SPFAnalysis);
	        this.dmarc = this.convertValues(source["dmarc"], DMARCAnalysis);
	        this.dkim = this.convertValues(source["dkim"], DKIMAnalysis);
	        this.rating = source["rating"];
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
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new RDAPInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.networkHandle = source["networkHandle"];
	        this.country = source["country"];
	        this.name = source["name"];
	        this.source = source["source"];
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
	    dkim?: DKIMRecord[];
	    ptr: Record<string, Array<string>>;
	    rdap?: RDAPInfo[];
	    errors?: string[];
	    emailPolicy?: EmailPolicyAnalysis;
	
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
	        this.dkim = this.convertValues(source["dkim"], DKIMRecord);
	        this.ptr = source["ptr"];
	        this.rdap = this.convertValues(source["rdap"], RDAPInfo);
	        this.errors = source["errors"];
	        this.emailPolicy = this.convertValues(source["emailPolicy"], EmailPolicyAnalysis);
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
	export class IPInformationResult {
	    ip: string;
	    addressClass: string;
	    reverseDns: string[];
	    rdap?: RDAPInfo;
	    sources: string[];
	    errors?: string[];
	
	    static createFrom(source: any = {}) {
	        return new IPInformationResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.addressClass = source["addressClass"];
	        this.reverseDns = source["reverseDns"];
	        this.rdap = this.convertValues(source["rdap"], RDAPInfo);
	        this.sources = source["sources"];
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
	
	
	export class StackFix {
	    file: string;
	    location: string;
	    before: string;
	    after: string;
	    deploy: string;
	    verify: string;
	    rollback: string;
	
	    static createFrom(source: any = {}) {
	        return new StackFix(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.file = source["file"];
	        this.location = source["location"];
	        this.before = source["before"];
	        this.after = source["after"];
	        this.deploy = source["deploy"];
	        this.verify = source["verify"];
	        this.rollback = source["rollback"];
	    }
	}
	export class RemediationEntry {
	    id: string;
	    title: BilingualText;
	    mechanism: BilingualText;
	    rootCause: BilingualText;
	    impact: BilingualText;
	    severity: string;
	    priority: string;
	    changeRisk: string;
	    prerequisites: BilingualTextList;
	    implementationNotes: BilingualTextList;
	    commonMistakes: BilingualTextList;
	    attackScenario: BilingualText;
	    attackSteps: BilingualTextList;
	    whereToFix: BilingualText;
	    verificationSteps: BilingualTextList;
	    falsePositiveNotes: BilingualText;
	    references: string[];
	    relatedFindings: string[];
	    stacks: Record<string, StackFix>;
	
	    static createFrom(source: any = {}) {
	        return new RemediationEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = this.convertValues(source["title"], BilingualText);
	        this.mechanism = this.convertValues(source["mechanism"], BilingualText);
	        this.rootCause = this.convertValues(source["rootCause"], BilingualText);
	        this.impact = this.convertValues(source["impact"], BilingualText);
	        this.severity = source["severity"];
	        this.priority = source["priority"];
	        this.changeRisk = source["changeRisk"];
	        this.prerequisites = this.convertValues(source["prerequisites"], BilingualTextList);
	        this.implementationNotes = this.convertValues(source["implementationNotes"], BilingualTextList);
	        this.commonMistakes = this.convertValues(source["commonMistakes"], BilingualTextList);
	        this.attackScenario = this.convertValues(source["attackScenario"], BilingualText);
	        this.attackSteps = this.convertValues(source["attackSteps"], BilingualTextList);
	        this.whereToFix = this.convertValues(source["whereToFix"], BilingualText);
	        this.verificationSteps = this.convertValues(source["verificationSteps"], BilingualTextList);
	        this.falsePositiveNotes = this.convertValues(source["falsePositiveNotes"], BilingualText);
	        this.references = source["references"];
	        this.relatedFindings = source["relatedFindings"];
	        this.stacks = this.convertValues(source["stacks"], StackFix, true);
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
	export class RemediationKnowledge {
	    version: string;
	    stacks: string[];
	    entries: RemediationEntry[];
	
	    static createFrom(source: any = {}) {
	        return new RemediationKnowledge(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.stacks = source["stacks"];
	        this.entries = this.convertValues(source["entries"], RemediationEntry);
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
	
	
	
	export class TakeoverClue {
	    subdomain: string;
	    cnameTarget: string;
	    provider: string;
	    status: string;
	    evidence: string;
	    remediation: string;
	
	    static createFrom(source: any = {}) {
	        return new TakeoverClue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subdomain = source["subdomain"];
	        this.cnameTarget = source["cnameTarget"];
	        this.provider = source["provider"];
	        this.status = source["status"];
	        this.evidence = source["evidence"];
	        this.remediation = source["remediation"];
	    }
	}
	export class SubdomainResult {
	    domain: string;
	    names: string[];
	    errors?: string[];
	    takeoverClues?: TakeoverClue[];
	
	    static createFrom(source: any = {}) {
	        return new SubdomainResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.names = source["names"];
	        this.errors = source["errors"];
	        this.takeoverClues = this.convertValues(source["takeoverClues"], TakeoverClue);
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
	    tls10Status: string;
	    tls11Status: string;
	    tls10Error?: string;
	    tls11Error?: string;
	    negotiatedProtocol?: string;
	    http2Supported: boolean;
	    http3Advertised: boolean;
	    http3Advertisement?: string;
	    weakTls12Ciphers?: string[];
	    weakCipherWarning?: string;
	
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
	        this.tls10Status = source["tls10Status"];
	        this.tls11Status = source["tls11Status"];
	        this.tls10Error = source["tls10Error"];
	        this.tls11Error = source["tls11Error"];
	        this.negotiatedProtocol = source["negotiatedProtocol"];
	        this.http2Supported = source["http2Supported"];
	        this.http3Advertised = source["http3Advertised"];
	        this.http3Advertisement = source["http3Advertisement"];
	        this.weakTls12Ciphers = source["weakTls12Ciphers"];
	        this.weakCipherWarning = source["weakCipherWarning"];
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
	
	export class WebAuditURLDiff {
	    url: string;
	    // Go type: time
	    latestAt?: any;
	    // Go type: time
	    previousAt?: any;
	    gradeChanged: boolean;
	    previousGrade?: string;
	    latestGrade?: string;
	    riskScoreDelta: number;
	    previousRiskScore: number;
	    latestRiskScore: number;
	    statusChanged: boolean;
	    previousStatus: number;
	    latestStatus: number;
	    newMissingHeaders: string[];
	    resolvedMissingHeaders: string[];
	    newFindingIds: string[];
	    resolvedFindingIds: string[];
	    certDaysDelta?: number;
	    previousCertDays?: number;
	    latestCertDays?: number;
	
	    static createFrom(source: any = {}) {
	        return new WebAuditURLDiff(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.latestAt = this.convertValues(source["latestAt"], null);
	        this.previousAt = this.convertValues(source["previousAt"], null);
	        this.gradeChanged = source["gradeChanged"];
	        this.previousGrade = source["previousGrade"];
	        this.latestGrade = source["latestGrade"];
	        this.riskScoreDelta = source["riskScoreDelta"];
	        this.previousRiskScore = source["previousRiskScore"];
	        this.latestRiskScore = source["latestRiskScore"];
	        this.statusChanged = source["statusChanged"];
	        this.previousStatus = source["previousStatus"];
	        this.latestStatus = source["latestStatus"];
	        this.newMissingHeaders = source["newMissingHeaders"];
	        this.resolvedMissingHeaders = source["resolvedMissingHeaders"];
	        this.newFindingIds = source["newFindingIds"];
	        this.resolvedFindingIds = source["resolvedFindingIds"];
	        this.certDaysDelta = source["certDaysDelta"];
	        this.previousCertDays = source["previousCertDays"];
	        this.latestCertDays = source["latestCertDays"];
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
	export class WebAuditDiff {
	    target: string;
	    // Go type: time
	    latestAt?: any;
	    // Go type: time
	    previousAt?: any;
	    urlDiffs: WebAuditURLDiff[];
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new WebAuditDiff(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.latestAt = this.convertValues(source["latestAt"], null);
	        this.previousAt = this.convertValues(source["previousAt"], null);
	        this.urlDiffs = this.convertValues(source["urlDiffs"], WebAuditURLDiff);
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
	

}

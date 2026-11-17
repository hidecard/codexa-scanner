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
	

}


export namespace logger {
	
	export class LogEntry {
	    timestamp: string;
	    level: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new LogEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.level = source["level"];
	        this.message = source["message"];
	    }
	}

}

export namespace models {
	
	export class WhitelistVM {
	    enabled: boolean;
	    paths: string[];
	
	    static createFrom(source: any = {}) {
	        return new WhitelistVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.paths = source["paths"];
	    }
	}
	export class ResponseSettingsVM {
	    autoTerminateEnabled: boolean;
	    criticalScoreThreshold: number;
	    investigationMode: boolean;
	    quarantineFiles: boolean;
	    quarantineDirectory: string;
	
	    static createFrom(source: any = {}) {
	        return new ResponseSettingsVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.autoTerminateEnabled = source["autoTerminateEnabled"];
	        this.criticalScoreThreshold = source["criticalScoreThreshold"];
	        this.investigationMode = source["investigationMode"];
	        this.quarantineFiles = source["quarantineFiles"];
	        this.quarantineDirectory = source["quarantineDirectory"];
	    }
	}
	export class DetectionThresholdsVM {
	    highEntropyFileThreshold: number;
	    ransomwareExtensionFileThreshold: number;
	    combinedEntropyAndExtensionThreshold: number;
	
	    static createFrom(source: any = {}) {
	        return new DetectionThresholdsVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.highEntropyFileThreshold = source["highEntropyFileThreshold"];
	        this.ransomwareExtensionFileThreshold = source["ransomwareExtensionFileThreshold"];
	        this.combinedEntropyAndExtensionThreshold = source["combinedEntropyAndExtensionThreshold"];
	    }
	}
	export class ConfigViewModel {
	    version: string;
	    lastUpdated: string;
	    detectionThresholds: DetectionThresholdsVM;
	    responseSettings: ResponseSettingsVM;
	    whitelist: WhitelistVM;
	    ransomwareExtensions: string[];
	
	    static createFrom(source: any = {}) {
	        return new ConfigViewModel(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.lastUpdated = source["lastUpdated"];
	        this.detectionThresholds = this.convertValues(source["detectionThresholds"], DetectionThresholdsVM);
	        this.responseSettings = this.convertValues(source["responseSettings"], ResponseSettingsVM);
	        this.whitelist = this.convertValues(source["whitelist"], WhitelistVM);
	        this.ransomwareExtensions = source["ransomwareExtensions"];
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
	export class DashboardStats {
	    protectionStatus: string;
	    sysmonConnected: boolean;
	    workerQueueDepth: number;
	    alertsProcessed: number;
	    processesTerminated: number;
	    filesQuarantined: number;
	    canaryFilesCount: number;
	    activeThreatsCount: number;
	
	    static createFrom(source: any = {}) {
	        return new DashboardStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.protectionStatus = source["protectionStatus"];
	        this.sysmonConnected = source["sysmonConnected"];
	        this.workerQueueDepth = source["workerQueueDepth"];
	        this.alertsProcessed = source["alertsProcessed"];
	        this.processesTerminated = source["processesTerminated"];
	        this.filesQuarantined = source["filesQuarantined"];
	        this.canaryFilesCount = source["canaryFilesCount"];
	        this.activeThreatsCount = source["activeThreatsCount"];
	    }
	}
	
	export class OperationResult {
	    success: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new OperationResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.message = source["message"];
	    }
	}
	

}


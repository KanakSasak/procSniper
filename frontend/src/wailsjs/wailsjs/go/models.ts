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
	    processes: string[];
	
	    static createFrom(source: any = {}) {
	        return new WhitelistVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.paths = source["paths"];
	        this.processes = source["processes"];
	    }
	}
	export class ResponseSettingsVM {
	    autoTerminateEnabled: boolean;
	    criticalScoreThreshold: number;
	    investigationMode: boolean;
	    quarantineFiles: boolean;
	    quarantineDirectory: string;
	    immediateResponse: boolean;
	    terminateOnExtensionMatch: boolean;
	    suspendBeforeTerminate: boolean;
	    detectionMode: string;
	    canaryResponseAction: string;
	
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
	        this.immediateResponse = source["immediateResponse"];
	        this.terminateOnExtensionMatch = source["terminateOnExtensionMatch"];
	        this.suspendBeforeTerminate = source["suspendBeforeTerminate"];
	        this.detectionMode = source["detectionMode"];
	        this.canaryResponseAction = source["canaryResponseAction"];
	    }
	}
	export class DetectionThresholdsVM {
	    highEntropyFileThreshold: number;
	    ransomwareExtensionFileThreshold: number;
	    ransomwareExtensionRenameThreshold: number;
	    combinedEntropyAndExtensionThreshold: number;
	    ioVelocityThresholdPerMinute: number;
	
	    static createFrom(source: any = {}) {
	        return new DetectionThresholdsVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.highEntropyFileThreshold = source["highEntropyFileThreshold"];
	        this.ransomwareExtensionFileThreshold = source["ransomwareExtensionFileThreshold"];
	        this.ransomwareExtensionRenameThreshold = source["ransomwareExtensionRenameThreshold"];
	        this.combinedEntropyAndExtensionThreshold = source["combinedEntropyAndExtensionThreshold"];
	        this.ioVelocityThresholdPerMinute = source["ioVelocityThresholdPerMinute"];
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
	export class EntropyStatsVM {
	    trackedFiles: number;
	    modifiedFiles: number;
	    significantIncreases: number;
	
	    static createFrom(source: any = {}) {
	        return new EntropyStatsVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.trackedFiles = source["trackedFiles"];
	        this.modifiedFiles = source["modifiedFiles"];
	        this.significantIncreases = source["significantIncreases"];
	    }
	}
	export class ETWDiagnosticsVM {
	    eventsReceived: number;
	    eventsDropped: number;
	    eventsSuppressedDeadPID: number;
	    workerPoolSize: number;
	    channelCapacity: number;
	    channelLength: number;
	
	    static createFrom(source: any = {}) {
	        return new ETWDiagnosticsVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.eventsReceived = source["eventsReceived"];
	        this.eventsDropped = source["eventsDropped"];
	        this.eventsSuppressedDeadPID = source["eventsSuppressedDeadPID"];
	        this.workerPoolSize = source["workerPoolSize"];
	        this.channelCapacity = source["channelCapacity"];
	        this.channelLength = source["channelLength"];
	    }
	}
	export class DashboardStats {
	    protectionStatus: string;
	    etwConnected: boolean;
	    workerQueueDepth: number;
	    alertsProcessed: number;
	    processesTerminated: number;
	    filesQuarantined: number;
	    canaryFilesCount: number;
	    activeThreatsCount: number;
	    autoResponsesBlocked: number;
	    highIOProcessCount: number;
	    etwDiagnostics: ETWDiagnosticsVM;
	    entropyStats: EntropyStatsVM;
	
	    static createFrom(source: any = {}) {
	        return new DashboardStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.protectionStatus = source["protectionStatus"];
	        this.etwConnected = source["etwConnected"];
	        this.workerQueueDepth = source["workerQueueDepth"];
	        this.alertsProcessed = source["alertsProcessed"];
	        this.processesTerminated = source["processesTerminated"];
	        this.filesQuarantined = source["filesQuarantined"];
	        this.canaryFilesCount = source["canaryFilesCount"];
	        this.activeThreatsCount = source["activeThreatsCount"];
	        this.autoResponsesBlocked = source["autoResponsesBlocked"];
	        this.highIOProcessCount = source["highIOProcessCount"];
	        this.etwDiagnostics = this.convertValues(source["etwDiagnostics"], ETWDiagnosticsVM);
	        this.entropyStats = this.convertValues(source["entropyStats"], EntropyStatsVM);
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
	
	
	
	export class IndicatorVM {
	    type: string;
	    severity: string;
	    points: number;
	    description: string;
	    timestamp: string;
	    evidence: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new IndicatorVM(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.severity = source["severity"];
	        this.points = source["points"];
	        this.description = source["description"];
	        this.timestamp = source["timestamp"];
	        this.evidence = source["evidence"];
	    }
	}
	export class MLModelStatus {
	    loaded: boolean;
	    filePath: string;
	    modelName: string;
	    modelType: string;
	    loadedAt: string;
	    enabled: boolean;
	    featureCount: number;
	    confidenceThreshold: number;
	
	    static createFrom(source: any = {}) {
	        return new MLModelStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.loaded = source["loaded"];
	        this.filePath = source["filePath"];
	        this.modelName = source["modelName"];
	        this.modelType = source["modelType"];
	        this.loadedAt = source["loadedAt"];
	        this.enabled = source["enabled"];
	        this.featureCount = source["featureCount"];
	        this.confidenceThreshold = source["confidenceThreshold"];
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
	
	export class ThreatViewModel {
	    processGuid: string;
	    processName: string;
	    processId: number;
	    score: number;
	    threatLevel: string;
	    category: string;
	    firstSeen: string;
	    lastSeen: string;
	    indicators: IndicatorVM[];
	
	    static createFrom(source: any = {}) {
	        return new ThreatViewModel(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.processGuid = source["processGuid"];
	        this.processName = source["processName"];
	        this.processId = source["processId"];
	        this.score = source["score"];
	        this.threatLevel = source["threatLevel"];
	        this.category = source["category"];
	        this.firstSeen = source["firstSeen"];
	        this.lastSeen = source["lastSeen"];
	        this.indicators = this.convertValues(source["indicators"], IndicatorVM);
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


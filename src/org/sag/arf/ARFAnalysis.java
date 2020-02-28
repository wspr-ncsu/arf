package org.sag.arf;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.sag.acminer.IACMinerDataAccessor;
import org.sag.acminer.database.accesscontrol.IContextQueryDatabase;
import org.sag.acminer.database.acminer.Doublet;
import org.sag.acminer.database.acminer.IACMinerDatabase;
import org.sag.acminer.database.entrypointedges.EntryPointContainer;
import org.sag.acminer.database.entrypointedges.EntryPointEdge;
import org.sag.acminer.database.entrypointedges.IEntryPointEdgesDatabase;
import org.sag.acminer.database.entrypointedges.SourceContainer;
import org.sag.acminer.database.excludedelements.IExcludeHandler;
import org.sag.acminer.phases.entrypoints.EntryPoint;
import org.sag.common.concurrent.IgnorableRuntimeException;
import org.sag.common.graphtools.AlElement.Color;
import org.sag.common.graphtools.GraphmlGenerator;
import org.sag.common.io.FileHelpers;
import org.sag.common.io.PrintStreamUnixEOL;
import org.sag.common.logging.ILogger;
import org.sag.common.tools.SortingMethods;
import org.sag.common.tuple.Pair;
import org.sag.main.config.Config;
import org.sag.main.phase.IPhaseHandler;
import org.sag.main.phase.IPhaseOption;
import org.sag.soot.analysis.AdvLocalDefs;
import org.sag.soot.analysis.FastDominatorsFinder;
import org.sag.soot.callgraph.ExcludingJimpleICFG.ExcludingEdgePredicate;
import org.sag.soot.xstream.SootClassContainer;
import org.sag.soot.xstream.SootMethodContainer;
import org.sag.soot.xstream.SootUnitContainer;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import soot.Body;
import soot.Local;
import soot.Scene;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.Unit;
import soot.Value;
import soot.jimple.BinopExpr;
import soot.jimple.DefinitionStmt;
import soot.jimple.IfStmt;
import soot.jimple.NewExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LiveLocals;

public class ARFAnalysis {
	
	private final IPhaseHandler handler;
	private final IACMinerDataAccessor dataAccessor;
	private final Config config;
	private final ILogger logger;
	private final String cn;
	private final IEntryPointEdgesDatabase ieepsDB;
	private final IACMinerDatabase acminerDB;
	private final IContextQueryDatabase cqdb;
	private SystemAndroidManifest systemAndroidManifest;
	private OnlyCallerRestrictions onlyCallerRestrictions;
	private Set<String> registeredServices;
	private List<Pair<String,String>> singleHopInput;
	private List<Pair<String,String>> knownVulnPaths;
	private Map<String,Pair<Set<String>,Set<String>>> specialCallerContextQueries;
	private Map<String,List<String>> methodToArgNames;
	private final boolean onlyPerm;
	private final boolean onlyPermString;
	private final boolean toGroup;
	private final boolean onlyUserPerm;
	private final boolean onlyCallerRes;
	private final boolean reachingGraph;
	private final boolean singleHop;
	private final boolean onlyRegisteredCallers;
	private final boolean onlyResultsReachingOthers;
	private final boolean removeDeputyTargetChecks;
	private final boolean testIfKnownVuln;
	private final boolean removeTargetsPartOfChecks;
	private final boolean removeSameCallingId;
	private final boolean removeGlobalSettingsNoise;
	private final boolean removeSpecialCallersRequired;
	private final boolean removeAlreadyHandelingMultiUser;
	private final boolean removeMultiUserNotNeeded;
	private final boolean wholeGraph;
	
	@SuppressWarnings("unchecked")
	private final Set<Pair<String,String>> allowedPairs = ImmutableSet.of(
		new Pair<>("<com.android.server.devicepolicy.DevicePolicyManagerService: void startManagedQuickContact(java.lang.String,long,boolean,long,android.content.Intent)>","<com.android.server.devicepolicy.DevicePolicyManagerService: boolean getCrossProfileCallerIdDisabledForUser(int)>"),
		new Pair<>("<com.android.server.devicepolicy.DevicePolicyManagerService: void startManagedQuickContact(java.lang.String,long,boolean,long,android.content.Intent)>","<com.android.server.devicepolicy.DevicePolicyManagerService: boolean getCrossProfileContactsSearchDisabledForUser(int)>"),
		new Pair<>("<com.android.server.trust.TrustManagerService$1: boolean isDeviceSecure(int)>","<com.android.server.locksettings.LockSettingsService: long getLong(java.lang.String,long,int)>"),
		new Pair<>("<com.android.server.trust.TrustManagerService$1: boolean isDeviceSecure(int)>","<com.android.server.locksettings.LockSettingsService: boolean havePassword(int)>"),
		new Pair<>("<com.android.server.trust.TrustManagerService$1: boolean isDeviceSecure(int)>","<com.android.server.locksettings.LockSettingsService: boolean havePattern(int)>"),
		new Pair<>("<com.android.server.fingerprint.FingerprintService$FingerprintServiceWrapper: java.util.List getEnrolledFingerprints(int,java.lang.String)>","<com.android.server.am.ActivityManagerService: android.content.pm.UserInfo getCurrentUser()>"),
		new Pair<>("<com.android.server.fingerprint.FingerprintService$FingerprintServiceWrapper: java.util.List getEnrolledFingerprints(int,java.lang.String)>","<com.android.server.am.ActivityManagerService: java.util.List getRunningAppProcesses()>"),
		new Pair<>("<com.android.server.fingerprint.FingerprintService$FingerprintServiceWrapper: java.util.List getEnrolledFingerprints(int,java.lang.String)>","<com.android.server.pm.UserManagerService: int[] getProfileIds(int,boolean)>"),
		new Pair<>("<com.android.server.pm.PackageManagerService: boolean isPackageDeviceAdminOnAnyUser(java.lang.String)>","<com.android.server.devicepolicy.DevicePolicyManagerService: android.content.ComponentName getDeviceOwnerComponent(boolean)>"),
		new Pair<>("<com.android.server.pm.PackageManagerService: boolean isPackageDeviceAdminOnAnyUser(java.lang.String)>","<com.android.server.devicepolicy.DevicePolicyManagerService: boolean packageHasActiveAdmins(java.lang.String,int)>"),
		new Pair<>("<com.android.server.am.ActivityManagerService: boolean switchUser(int)>","<com.android.server.pm.UserManagerService: android.content.pm.UserInfo getUserInfo(int)>"),
		new Pair<>("<com.android.server.notification.NotificationManagerService$7: boolean areNotificationsEnabledForPackage(java.lang.String,int)>","<com.android.server.pm.PackageManagerService: android.content.pm.ApplicationInfo getApplicationInfo(java.lang.String,int,int)>"), //Special case of having the check but not using it properly
		new Pair<>("<com.android.server.media.MediaResourceMonitorService$MediaResourceMonitorImpl: void notifyResourceGranted(int,int)>","<com.android.server.am.ActivityManagerService: android.content.pm.UserInfo getCurrentUser()>"), //Special case where it is sending out a broadcast to all users
		new Pair<>("<com.android.server.notification.NotificationManagerService$7: void enqueueNotificationWithTag(java.lang.String,java.lang.String,java.lang.String,int,android.app.Notification,int)>","<com.android.server.am.ActivityManagerService: void setProcessImportant(android.os.IBinder,int,boolean,java.lang.String)>"), //Special case of having the check but not using it properly
		new Pair<>("<com.android.server.devicepolicy.DevicePolicyManagerService: void startManagedQuickContact(java.lang.String,long,boolean,long,android.content.Intent)>","<com.android.server.pm.PackageManagerService: android.content.pm.ApplicationInfo getApplicationInfo(java.lang.String,int,int)>") //Special case of leaking data from other users
	);
	
	public ARFAnalysis(IACMinerDataAccessor dataAccessor, IPhaseHandler handler, ILogger mainLogger) {
		this.handler = handler;
		this.dataAccessor = dataAccessor;
		this.config = dataAccessor.getConfig();
		this.logger = mainLogger;
		this.cn = getClass().getSimpleName();
		this.ieepsDB = dataAccessor.getEntryPointEdgesDB();
		this.acminerDB = dataAccessor.getACMinerDB();
		this.systemAndroidManifest = null;
		this.onlyCallerRestrictions = null;
		this.registeredServices = null;
		this.singleHopInput = null;
		this.knownVulnPaths = null;
		this.cqdb = dataAccessor.getContextQueriesDB();
		this.specialCallerContextQueries = null;
		this.methodToArgNames = null;
		this.onlyPerm = isOptionEnabled(ARFHandler.optPerm);
		this.onlyPermString = isOptionEnabled(ARFHandler.optPermString);
		this.toGroup = isOptionEnabled(ARFHandler.optGroup);
		this.onlyUserPerm = isOptionEnabled(ARFHandler.optOnlyUserPerm);
		this.onlyCallerRes = isOptionEnabled(ARFHandler.optOnlyCallerRes);
		this.reachingGraph = isOptionEnabled(ARFHandler.optReachingGraph);
		this.singleHop = isOptionEnabled(ARFHandler.optSingleHop);
		this.onlyRegisteredCallers = isOptionEnabled(ARFHandler.optOnlyRegisteredCallers);
		this.onlyResultsReachingOthers = isOptionEnabled(ARFHandler.optOnlyResultsReachingOthers);
		this.removeDeputyTargetChecks = isOptionEnabled(ARFHandler.optRemoveDeputyTargetChecks);
		this.testIfKnownVuln = isOptionEnabled(ARFHandler.optTestIfKnownVuln);
		this.removeTargetsPartOfChecks = isOptionEnabled(ARFHandler.optRemoveTargetsPartOfChecks);
		this.removeSameCallingId = isOptionEnabled(ARFHandler.optRemoveSameCallingId);
		this.removeGlobalSettingsNoise = isOptionEnabled(ARFHandler.optRemoveGlobalSettingsNoise);
		this.removeSpecialCallersRequired = isOptionEnabled(ARFHandler.optRemoveSpecialCallersRequired);
		this.removeAlreadyHandelingMultiUser = isOptionEnabled(ARFHandler.optRemoveAlreadyHandelingMultiUser);
		this.removeMultiUserNotNeeded = isOptionEnabled(ARFHandler.optRemoveMultiUserNotNeeded);
		this.wholeGraph = isOptionEnabled(ARFHandler.optWholeGraph);
	}
	
	private boolean isOptionEnabled(String name) {
		IPhaseOption<?> o = handler.getPhaseOptionUnchecked(name);
		if(o == null || !o.isEnabled())
			return false;
		return true;
	}
	
	public boolean init() {
		if(onlyUserPerm) {
			Path manifest = config.getFilePath("work_system-android-manifest-file");
			try {
				FileHelpers.verifyRWFileExists(manifest);
			} catch(Throwable t) {
				logger.fatal("{}: Could not access the system AndroidManifest file at '{}'.",t,cn,
						manifest);
				return false;
			}
			
			try {
				systemAndroidManifest = SystemAndroidManifest.readXMLStatic(null, manifest);
			} catch(Throwable t) {
				logger.fatal("{}: Could not read the system AndroidManifest file at '{}'.",t,cn,
						manifest);
				return false;
			}
		}
		
		if(onlyCallerRes) {
			Path p = config.getFilePath("arf_only-caller-restrictions-file");
			try {
				FileHelpers.verifyRWFileExists(p);
			} catch(Throwable t) {
				logger.fatal("{}: Could not access the only caller restrictions file at '{}'.",t,cn,
						p);
				return false;
			}
			
			try {
				onlyCallerRestrictions = OnlyCallerRestrictions.parser(p);
			} catch(Throwable t) {
				logger.fatal("{}: Could not read the only caller restrictions file at '{}'.",t,cn,
						p);
				return false;
			}
		}
		
		if(onlyRegisteredCallers) {
			Path p = config.getFilePath("acminer_registered-services-temp-file");
			try {
				FileHelpers.verifyRWFileExists(p);
			} catch(Throwable t) {
				logger.fatal("{}: Could not access the registered services file at '{}'.",t,cn,
						p);
				return false;
			}
			
			try {
				try(BufferedReader br = Files.newBufferedReader(p)) {
					this.registeredServices = new HashSet<>();
					String line;
					while((line = br.readLine()) != null) {
						line = line.trim();
						if(!line.isEmpty() && !line.startsWith("//"))
							this.registeredServices.add(line);
					}
				}
				this.registeredServices = SortingMethods.sortSet(this.registeredServices,SortingMethods.sComp);
			} catch(Throwable t) {
				logger.fatal("{}: Could not read the registered services file at '{}'.",t,cn,
						p);
				return false;
			}
		}
		
		if(onlyResultsReachingOthers) {
			Path p = config.getFilePath("arf_single-hop-temp-file");
			try {
				FileHelpers.verifyRWFileExists(p);
			} catch(Throwable t) {
				logger.fatal("{}: Could not access the single hop relationships file at '{}'.",t,cn,
						p);
				return false;
			}
			
			try {
				try(BufferedReader br = Files.newBufferedReader(p)) {
					this.singleHopInput = new ArrayList<>();
					String line;
					while((line = br.readLine()) != null) {
						line = line.trim();
						if(!line.isEmpty() && !line.startsWith("//")) {
							String[] temp = line.split("\\t");
							this.singleHopInput.add(new Pair<>(temp[0].trim(),temp[1].trim()));
						}
					}
				}
			} catch(Throwable t) {
				logger.fatal("{}: Could not read the sinlge hip relationships file at '{}'.",t,cn,
						p);
				return false;
			}
		}
		
		if(testIfKnownVuln) {
			Path p = config.getFilePath("arf_known-vuln-paths-temp-file");
			try(BufferedReader br = Files.newBufferedReader(p)) {
				this.knownVulnPaths = new ArrayList<>();
				String line;
				while((line = br.readLine()) != null) {
					line = line.trim();
					if(!line.isEmpty() && !line.startsWith("//")) {
						String[] temp = line.split("\\t");
						this.knownVulnPaths.add(new Pair<>(temp[0].trim(),temp[1].trim()));
					}
				}
			} catch(Throwable t) {
				logger.fatal("{}: Could not read known vuln paths file at '{}'.",t,cn,
						p);
				return false;
			}
		}
		
		if(removeSpecialCallersRequired) {
			Path path = config.getFilePath("arf_special-caller-context-queries-temp-file");
			try(BufferedReader br = Files.newBufferedReader(path)) {
				specialCallerContextQueries = new HashMap<>();
				String line;
				while((line = br.readLine()) != null) {
					line = line.trim();
					if(!line.isEmpty() && !line.startsWith("//")) {
						String[] temp = line.split("\\t");
						Pair<Set<String>,Set<String>> p = specialCallerContextQueries.get(temp[0].trim());
						if(p == null) {
							p = new Pair<>(new HashSet<>(),new HashSet<>());
							specialCallerContextQueries.put(temp[0].trim(),p);
						}
						p.getFirst().add(temp[1].trim());
						if(temp.length > 2) {
							for(int i = 2; i < temp.length; i++) {
								p.getSecond().add(temp[i].trim());
							}
						}
					}
				}
			} catch(Throwable t) {
				logger.fatal("{}: Could not read the special caller context query file at '{}'.",t,cn,
						path);
				return false;
			}
		}
		
		if(removeMultiUserNotNeeded) {
			Path p = config.getFilePath("arf_methods-with-arg-names-temp-file");
			try(BufferedReader br = Files.newBufferedReader(p)) {
				methodToArgNames = new HashMap<>();
				String line;
				while((line = br.readLine()) != null) {
					line = line.trim();
					if(!line.isEmpty() && !line.startsWith("//")) {
						String[] temp = line.split("\\t");
						String sig = temp[0].trim();
						String names = temp[1].trim();
						String[] argNames = names.replace("[", "").replace("]", "").split(", ");
						for(int i = 0; i < argNames.length; i++)
							argNames[i] = argNames[i].trim();
						methodToArgNames.put(sig, Arrays.asList(argNames));
					}
				}
			} catch(Throwable t) {
				logger.fatal("{}: Could not read known method argument names at '{}'.",t,cn,
						p);
				return false;
			}
		}
		
		Path debugDir = config.getFilePath("debug-dir");
		try {
			FileHelpers.processDirectory(debugDir, true, false);
		} catch(Throwable t) {
			logger.fatal("{}: Could not access debug directory '{}'.",t,cn,
					debugDir);
			return false;
		}
		
		Path outDir = config.getFilePath("debug_arf-dir");
		try {
			FileHelpers.processDirectory(outDir, true, false);
		} catch(Throwable t) {
			logger.fatal("{}: Could not access arf output directory '{}'.",t,cn,
					outDir);
			return false;
		}
		
		if(reachingGraph || wholeGraph) {
			Path p = config.getFilePath("debug_arf-graph-dir");
			try {
				FileHelpers.processDirectory(p, true, false);
			} catch(Throwable t) {
				logger.fatal("{}: Could not access arf graph output directory '{}'.",t,cn,
						p);
				return false;
			}
		}
		return true;
	}
	
	public Map<EntryPointNode, Set<Doublet>> keepOnlyPermDoublet(Map<EntryPointNode, Set<Doublet>> in) {
		Map<EntryPointNode, Set<Doublet>> ret = new LinkedHashMap<>();
		for(EntryPointNode ep : in.keySet()) {
			Set<Doublet> keep = new LinkedHashSet<>();
			for(Doublet d : in.get(ep)) {
				if(d.toString().contains("<com.android.server.pm.PackageManagerService: int checkUidPermission(java.lang.String,int)>("))
					keep.add(d);
			}
			ret.put(ep, SortingMethods.sortSet(keep));
		}
		return ret;
	}
	
	public Map<EntryPointNode, Set<Doublet>> keepOnlyPermString(Map<EntryPointNode, Set<Doublet>> in) {
		String permCheckSig = "<com.android.server.pm.PackageManagerService: int checkUidPermission(java.lang.String,int)>(";
		Map<EntryPointNode, Set<Doublet>> ret = new LinkedHashMap<>();
		for(EntryPointNode ep : in.keySet()) {
			Map<String,Map<SootMethodContainer,Map<String,SootUnitContainer>>> exprToSources = new HashMap<>();
			for(Doublet d : in.get(ep)) {
				String expr = d.toString();
				if(expr.contains(permCheckSig)) {
					int i = expr.indexOf(permCheckSig);
					if(i != 1)
						throw new RuntimeException(d.toString());
					i += permCheckSig.length();
					int startIndex = i;
					int endIndex = -1;
					char startChar = expr.charAt(i);
					
					if(startChar == '"') {
						boolean inQuote = false;
						for(; i < expr.length(); i++) {
							char cur = expr.charAt(i);
							if(cur == startChar) {
								if(!inQuote) {
									inQuote = true;
								} else {
									inQuote = false;
									break;
								}
							}
						}
						if(inQuote || i >= expr.length())
							throw new RuntimeException("Error: Failed to parse '" + expr + "'.");
					} else if(startChar == '<') {
						int depth = 0;
						char endChar = '>';
						for(; i < expr.length(); i++) {
							char cur = expr.charAt(i);
							if(cur == startChar)
								depth++;
							else if(cur == endChar)
								depth--;
							if(depth <= 0)
								break;
						}
						if(depth > 0 || i >= expr.length())
							throw new RuntimeException("Error: Failed to parse '" + expr + "'.");
					} else if(startChar == 'A') {
						if(expr.length() < i + 4 || expr.charAt(i+1) != 'L' || expr.charAt(i+2) != 'L' || expr.charAt(i+3) != ',')
							throw new RuntimeException("Error: Failed to parse '" + expr + "'.");
						i += 2;
					} else {
						throw new RuntimeException("Error: Unhandled start char '" + startChar + "' in '" + expr + "'.");
					}
					endIndex = i;
					
					Set<String> newExprs = new HashSet<>();
					String newExpr = "`" + expr.substring(startIndex, endIndex + 1) + "`";
					if(newExpr.equals("`<com.android.server.location.FusedLocationHardwareSecure: java.lang.String mPermissionId>`")) {
						newExprs.add("`\"android.permission.LOCATION_HARDWARE\"`"); //Only defined once in the FusedProxy class Android 8.0.1
					} else if(newExpr.equals("`<android.provider.Settings: java.lang.String[] PM_WRITE_SETTINGS>`")) {
						newExprs.add("`\"android.permission.WRITE_SETTINGS\"`"); //Array only has one permission in it in Android 8.0.1
					} else if(newExpr.equals("`ALL`")) {
						//All because the permission check function takes in an array of permissions that if any pass then the caller is allowed
						if(ep.getEntryPoint().getSignature().equals("<com.android.server.accounts.AccountManagerService: void startAddAccountSession(android.accounts.IAccountManagerResponse,java.lang.String,java.lang.String,java.lang.String[],boolean,android.os.Bundle)>")) {
							newExprs.add("`\"android.permission.GET_PASSWORD\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.accounts.AccountManagerService: void startUpdateCredentialsSession(android.accounts.IAccountManagerResponse,android.accounts.Account,java.lang.String,boolean,android.os.Bundle)>")) {
							newExprs.add("`\"android.permission.GET_PASSWORD\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: boolean getPersistentVrModeEnabled()>")) {
							newExprs.add("`\"android.permission.ACCESS_VR_MANAGER\"`");
							newExprs.add("`\"android.permission.ACCESS_VR_STATE\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: boolean getVrModeState()>")) {
							newExprs.add("`\"android.permission.ACCESS_VR_MANAGER\"`");
							newExprs.add("`\"android.permission.ACCESS_VR_STATE\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: void registerListener(android.service.vr.IVrStateCallbacks)>")) {
							newExprs.add("`\"android.permission.ACCESS_VR_MANAGER\"`");
							newExprs.add("`\"android.permission.ACCESS_VR_STATE\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: void registerPersistentVrStateListener(android.service.vr.IPersistentVrStateCallbacks)>")) {
							newExprs.add("`\"android.permission.ACCESS_VR_MANAGER\"`");
							newExprs.add("`\"android.permission.ACCESS_VR_STATE\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: void setAndBindCompositor(java.lang.String)>")) {
							newExprs.add("`\"android.permission.RESTRICTED_VR_ACCESS\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: void setPersistentVrModeEnabled(boolean)>")) {
							newExprs.add("`\"android.permission.RESTRICTED_VR_ACCESS\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: void setVr2dDisplayProperties(android.app.Vr2dDisplayProperties)>")) {
							newExprs.add("`\"android.permission.RESTRICTED_VR_ACCESS\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: void unregisterListener(android.service.vr.IVrStateCallbacks)>")) {
							newExprs.add("`\"android.permission.ACCESS_VR_MANAGER\"`");
							newExprs.add("`\"android.permission.ACCESS_VR_STATE\"`");
						} else if(ep.getEntryPoint().getSignature().equals("<com.android.server.vr.VrManagerService$4: void unregisterPersistentVrStateListener(android.service.vr.IPersistentVrStateCallbacks)>")) {
							newExprs.add("`\"android.permission.ACCESS_VR_MANAGER\"`");
							newExprs.add("`\"android.permission.ACCESS_VR_STATE\"`");
						}
					}
					if(newExprs.isEmpty())
						newExprs.add(newExpr);
					
					for(String ne : newExprs) {
						Map<SootMethodContainer,Map<String,SootUnitContainer>> sources = exprToSources.get(ne);
						if(sources == null) {
							sources = new HashMap<>();
							exprToSources.put(ne, sources);
						}
						Map<SootMethodContainer,Map<String,SootUnitContainer>> temp = d.getSources();
						for(SootMethodContainer sourceMethod : temp.keySet()) {
							Map<String,SootUnitContainer> units = sources.get(sourceMethod);
							if(units == null) {
								units = new HashMap<>();
								sources.put(sourceMethod, units);
							}
							units.putAll(temp.get(sourceMethod));
						}
					}
				}
			}
			Set<Doublet> keep = new HashSet<>();
			for(String expr : exprToSources.keySet()) {
				keep.add(new Doublet(expr, exprToSources.get(expr)));
			}
			ret.put(ep, SortingMethods.sortSet(keep));
		}
		return ret;
	}
	
	public boolean outResultsNormal(Set<ResultContainer> results) {
		Set<ResultContainer> lower25 = new LinkedHashSet<>();
		Set<ResultContainer> lower50 = new LinkedHashSet<>();
		Set<ResultContainer> lower75 = new LinkedHashSet<>();
		Set<ResultContainer> lower100 = new LinkedHashSet<>();
		Set<ResultContainer> all100 = new LinkedHashSet<>();
		for(ResultContainer r : results) {
			if(r.getRatio() > 0 && r.getRatio() <= 0.25)
				lower25.add(r);
			else if(r.getRatio() > 0.25 && r.getRatio() <= 0.5)
				lower50.add(r);
			else if(r.getRatio() > 0.5 && r.getRatio() <= 0.75)
				lower75.add(r);
			else if(r.getRatio() > 0.75 && r.getRatio() < 1)
				lower100.add(r);
			else
				all100.add(r);
		}
		lower25 = SortingMethods.sortSet(lower25);
		lower50 = SortingMethods.sortSet(lower50);
		lower75 = SortingMethods.sortSet(lower75);
		lower100 = SortingMethods.sortSet(lower100);
		all100 = SortingMethods.sortSet(all100);
		
		Path summaryPath = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "summary.txt");
		Path lower25Path = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "lower_25.txt");
		Path lower50Path = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "lower_50.txt");
		Path lower75Path = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "lower_75.txt");
		Path lower100Path = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "lower_100.txt");
		Path allChecksMissingPath = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "all_checks_missing.txt");
		
		try {
			dumpResultsSet(all100,allChecksMissingPath);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,allChecksMissingPath);
			return false;
		}
		try {
			dumpResultsSet(lower25,lower25Path);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,lower25Path);
			return false;
		}
		try {
			dumpResultsSet(lower50,lower50Path);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,lower50Path);
			return false;
		}
		try {
			dumpResultsSet(lower75,lower75Path);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,lower75Path);
			return false;
		}
		try {
			dumpResultsSet(lower100,lower100Path);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,lower100Path);
			return false;
		}
		try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(summaryPath))) {
			ps.println("Total: " + results.size());
			ps.println("All Checks Missing: " + all100.size());
			ps.println("(0,0.25] Ratio: " + lower25.size());
			ps.println("(0.25,0.50] Ratio: " + lower50.size());
			ps.println("(0.50,0.75] Ratio: " + lower75.size());
			ps.println("(0.75,1) Ratio: " + lower100.size());
			ps.println("Missing Some Checks: " + (lower100.size() + lower75.size() + lower50.size() 
				+ lower25.size() + all100.size()));
			
			ps.println("\nAll Checks Missing:");
			for(ResultContainer r : all100) {
				ps.println("  (Missing, Ratio): (" + r.getMissingChecks().size() + ", " + r.getRatio() + ") " + r.getCallerEp() + " ---> " + r.getTargetEp());
			}
			
			ps.println("(0.75,1) Ratio:");
			for(ResultContainer r : lower100) {
				ps.println("  (Missing, Ratio): (" + r.getMissingChecks().size() + ", " + r.getRatio() + ") " + r.getCallerEp() + " ---> " + r.getTargetEp());
			}
			
			ps.println("\n(0.50,0.75] Ratio:");
			for(ResultContainer r : lower75) {
				ps.println("  (Missing, Ratio): (" + r.getMissingChecks().size() + ", " + r.getRatio() + ") " + r.getCallerEp() + " ---> " + r.getTargetEp());
			}
			
			ps.println("\n(0.25,0.50] Ratio:");
			for(ResultContainer r : lower50) {
				ps.println("  (Missing, Ratio): (" + r.getMissingChecks().size() + ", " + r.getRatio() + ") " + r.getCallerEp() + " ---> " + r.getTargetEp());
			}
			
			ps.println("\n(0,0.25] Ratio:");
			for(ResultContainer r : lower25) {
				ps.println("  (Missing, Ratio): (" + r.getMissingChecks().size() + ", " + r.getRatio() + ") " + r.getCallerEp() + " ---> " + r.getTargetEp());
			}
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,summaryPath);
			return false;
		}
		return true;
	}
	
	public boolean outTSV(Set<ResultContainer> results, Map<ResultContainer,GroupContainer> resultToGroup) {
		Map<EntryPointNode,Map<EntryPointNode,Set<ResultContainer>>> callerToTargetToResults = new HashMap<>();
		for(ResultContainer r : results) {
			if(!r.isEmptyResult() && r.getRatio() != 0.0) {
				EntryPointNode caller = r.getCallerEp();
				EntryPointNode target = r.getTargetEp();
				Map<EntryPointNode,Set<ResultContainer>> targetToResults = callerToTargetToResults.get(caller);
				if(targetToResults == null) {
					targetToResults = new HashMap<>();
					callerToTargetToResults.put(caller, targetToResults);
				}
				Set<ResultContainer> rtemp = targetToResults.get(target);
				if(rtemp == null) {
					rtemp = new HashSet<>();
					targetToResults.put(target, rtemp);
				}
				rtemp.add(r);
			}
		}
		for(EntryPointNode caller : callerToTargetToResults.keySet()) {
			Map<EntryPointNode, Set<ResultContainer>> targetToResults = callerToTargetToResults.get(caller);
			for(EntryPointNode target : targetToResults.keySet()) {
				targetToResults.put(target, SortingMethods.sortSet(targetToResults.get(target), new ResultContainer.SortByDoubletRatio()));
			}
			callerToTargetToResults.put(caller, SortingMethods.sortMapKeyAscending(targetToResults));
		}
		callerToTargetToResults = SortingMethods.sortMapKeyAscending(callerToTargetToResults);
		
		Pattern permPattern = Pattern.compile("^`\"([^`\"]+)\"`$");
		Path tsvPath = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "results.tsv");
		try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(tsvPath))) {
			if(resultToGroup != null && !resultToGroup.isEmpty()) {
				ps.print("Group\t");
			}
			boolean hasPath = false;
			for(EntryPointNode caller : callerToTargetToResults.keySet()) {
				Map<EntryPointNode,Set<ResultContainer>> targetToResults = callerToTargetToResults.get(caller);
				for(EntryPointNode target : targetToResults.keySet()) {
					for(ResultContainer r : targetToResults.get(target)) {
						List<EntryPointNode> path = r.getPath();
						if(path != null && !path.isEmpty()) {
							hasPath = true;
							break;
						}
					}
					if(hasPath)
						break;
				}
				if(hasPath)
					break;
			}
			
			ps.print("Ratio\tCaller Stub\tCaller Service\tCaller Name\tCaller Signature\tTarget Stub\tTarget Service\tTarget Name\tTarget Signature\tMissingChecks\tSources");
			if(hasPath)
				ps.print("\tPath");
			ps.print("\r");
			for(EntryPointNode caller : callerToTargetToResults.keySet()) {
				Map<EntryPointNode,Set<ResultContainer>> targetToResults = callerToTargetToResults.get(caller);
				for(EntryPointNode target : targetToResults.keySet()) {
					for(ResultContainer r : targetToResults.get(target)) {
						if(resultToGroup != null && !resultToGroup.isEmpty()) {
							ps.print(resultToGroup.get(r).getName() + "\t");
						}
						ps.print(r.getRatio() + "\t");
						
						ps.print(caller.getStub().getSignature() + "\t");
						ps.print(caller.getEntryPoint().getDeclaringClass() + "\t");
						ps.print(caller.getEntryPoint().getName() + "\t");
						ps.print(caller.getEntryPoint().getSignature() + "\t");
						
						/*StringBuilder callerString = new StringBuilder();
						callerString.append("\"");
						callerString.append("Class: ").append(caller.getDeclaringClass()).append("\n");
						callerString.append("Name: ").append(caller.getName()).append("\n");
						callerString.append("RetType: ").append(caller.getReturnType()).append("\n");
						callerString.append("ArgTypes:");
						for(String arg : caller.getArgumentTypes()) {
							callerString.append("\n  ").append(arg);
						}
						callerString.append("\"");
						ps.print(callerString.toString() + "\t");*/
						
						ps.print(target.getStub().getSignature() + "\t");
						ps.print(target.getEntryPoint().getDeclaringClass() + "\t");
						ps.print(target.getEntryPoint().getName() + "\t");
						ps.print(target.getEntryPoint().getSignature() + "\t");
						
						/*StringBuilder targetString = new StringBuilder();
						targetString.append("\"");
						targetString.append("Class: ").append(target.getDeclaringClass()).append("\n");
						targetString.append("Name: ").append(target.getName()).append("\n");
						targetString.append("RetType: ").append(target.getReturnType()).append("\n");
						targetString.append("ArgTypes:");
						for(String arg : target.getArgumentTypes()) {
							targetString.append("\n  ").append(arg);
						}
						targetString.append("\"");
						ps.print(targetString.toString() + "\t");*/
						
						
						StringBuilder missingChecks = new StringBuilder();
						StringBuilder sources = new StringBuilder();
						missingChecks.append("\"");
						sources.append("\"");
						boolean first = true;
						for(Doublet d : SortingMethods.sortSet(r.getMissingChecks())) {
							String s = d.toString();
							Matcher m = permPattern.matcher(s);
							if(m.matches()) {
								s = m.group(1);
							} else {
								s = s.replace('"', '\'').replace("`", "");
							}
							if(first) {
								first = false;
							} else {
								missingChecks.append("\n");
								sources.append("\n");
							}
							missingChecks.append(s);
							sources.append(s);
							for(SootMethodContainer source : SortingMethods.sortSet(d.getSourceMethodContainers())) {
								sources.append("\n  ").append(source.getDeclaringClass()).append(" : ").append(source.getName());
							}
						}
						missingChecks.append("\"");
						sources.append("\"");
						ps.print(missingChecks.toString() + "\t");
						ps.print(sources.toString() + "\t");
						
						StringBuilder pathStr = new StringBuilder();
						first = true;
						pathStr.append("\"");
						for(EntryPointNode s : r.getPath()) {
							if(first) {
								first = false;
							} else {
								pathStr.append("\n");
							}
							pathStr.append(s);
						}
						pathStr.append("\"");
						ps.print(pathStr.toString() + "\r");
						
					}
				}
			}
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,tsvPath);
			return false;
		}
		return true;
	}
	
	public Map<ResultContainer,GroupContainer> outResultsGroup(Set<ResultContainer> results) {
		Map<Set<Doublet>,GroupContainer> missingChecksToGroup = new HashMap<>();
		Map<ResultContainer,GroupContainer> ret = new HashMap<>();
		for(ResultContainer r : results) {
			Set<Doublet> missingChecks = r.getMissingChecks();
			GroupContainer g = missingChecksToGroup.get(missingChecks);
			if(g == null) {
				try {
				g = new GroupContainer(FileHelpers.getHashOfString("MD5", missingChecks.toString()), missingChecks);
				} catch(Throwable t) {
					logger.fatal("{}: Exception when generating group name for {}",t,cn,missingChecks.toString());
					return null;
				}
				missingChecksToGroup.put(missingChecks, g);
			}
			g.addResult(r);
			ret.put(r, g);
		}
		Set<GroupContainer> groups = new HashSet<>();
		for(GroupContainer g : missingChecksToGroup.values()) {
			g.finalizeData();
			groups.add(g);
		}
		groups = SortingMethods.sortSet(groups);
		
		Path summaryPath = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "summary.txt");
		try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(summaryPath))) {
			ps.println("Total: " + results.size());
			ps.println("Some Missing Checks: " + results.size());
			ps.println("Groups: " + groups.size());
			
			for(GroupContainer g : groups) {
				ps.print(g.toString());
			}
			
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,summaryPath);
			return null;
		}
		
		return ret;
	}
	
	private boolean outputCallersWithMissingChecks(Set<ResultContainer> results) {
		Path callersWithMissingChecksPath = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "callers_with_missing_checks.txt");
		Set<EntryPointNode> callers = new HashSet<>();
		for(ResultContainer r : results) {
			if(!r.isEmptyResult() && r.getRatio() != 0.0)
				callers.add(r.getCallerEp());
		}
		try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(callersWithMissingChecksPath))) {
			for(EntryPointNode sc : callers) {
				ps.println(sc);
			}
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,callersWithMissingChecksPath);
			return false;
		}
		return true;
	}
	
	private boolean outputCallersWithNoPermissionChecks(Set<ResultContainer> results, Map<EntryPointNode, Set<Doublet>> epsToAuthLogicPermOnly) {
		Path callersWithNoPermissionChecks = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "callers_with_no_permission_checks.txt");
		Path callersWithNoPermissionChecksWithSources = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "callers_with_no_permission_checks_with_sources.txt");
		Map<EntryPointNode, Set<Doublet>> epsToAuthLogic = getEpsToAuthLogic(acminerDB.getValuePairs());
		Set<EntryPointNode> callers = new HashSet<>();
		for(ResultContainer r : results) {
			Set<Doublet> ds = epsToAuthLogicPermOnly.get(r.getCallerEp());
			if(!r.isEmptyResult() && r.getRatio() != 0.0 && (ds == null || ds.isEmpty()))
				callers.add(r.getCallerEp());
		}
		callers = SortingMethods.sortSet(callers, new Comparator<EntryPointNode>() {
			@Override
			public int compare(EntryPointNode o1, EntryPointNode o2) {
				Set<Doublet> checks1 = epsToAuthLogic.get(o1);
				Set<Doublet> checks2 = epsToAuthLogic.get(o2);
				int ret = Integer.compare(checks1 == null ? 0 : checks1.size(), checks2 == null ? 0 : checks2.size());
				if(ret == 0)
					ret = o1.compareTo(o2);
				return ret;
			}
		});
		try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(callersWithNoPermissionChecks))) {
			for(EntryPointNode sc : callers) {
				Set<Doublet> checks = epsToAuthLogic.get(sc);
				ps.println("Caller: " + sc + " Size: " + (checks == null ? 0 : checks.size()));
				if(checks != null) {
					for(Doublet d : checks) {
						ps.println("  " + d.toString());
					}
				}
			}
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,callersWithNoPermissionChecks);
			return false;
		}
		try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(callersWithNoPermissionChecksWithSources))) {
			for(EntryPointNode sc : callers) {
				Set<Doublet> checks = epsToAuthLogic.get(sc);
				ps.println("Caller: " + sc + " Size: " + (checks == null ? 0 : checks.size()));
				if(checks != null) {
					for(Doublet d : checks) {
						ps.println("  " + d.toString());
						for(String s : d.getSourceMethods()) {
							ps.println("    " + s);
						}
					}
				}
			}
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,callersWithNoPermissionChecksWithSources);
			return false;
		}
		return true;
	}
	
	private void outputGraph(Map<EntryPointNode, Set<EntryPointNode>> allEpsToEps) {
		ReachingCGTransformer trans = new ReachingCGTransformer(ieepsDB);
		trans.transform();
		trans.setExtraDataToCallSources();
		int i = 0;
		for(EntryPointNode ep : SortingMethods.sortSet(allEpsToEps.keySet())) {
			if(!allEpsToEps.get(ep).isEmpty()) {
				Map<EntryPointNode,List<Color>> colorMap = new HashMap<>();
				colorMap.put(ep, Collections.singletonList(Color.GREEN));
				long nodeColorIndex = trans.applyColorsToNodes(colorMap);
				Path out = getOutputFilePath(config.getFilePath("debug_arf-graph-dir"), ep.getEntryPoint(), i++ + "", ".graphml");
				ReachingCGFormatter formatter = new ReachingCGFormatter(ep, trans, 0, nodeColorIndex, trans.getExtraDataIndex(ep), out);
				formatter.format();
				GraphmlGenerator.outputGraphStatic(formatter);
			}
		}
	}
	
	private void outputWholeGraph(Map<EntryPointNode, Set<EntryPointNode>> directlyCalledEpsForEps) {
		MultiPathCGTransformer trans = new MultiPathCGTransformer(directlyCalledEpsForEps);
		trans.transform();
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-graph-dir"),"whole_graph.graphml");
		MultiPathCGFormatter formatter = new MultiPathCGFormatter(trans,out);
		GraphmlGenerator.outputGraphStatic(formatter);
	}
	
	private Path getOutputFilePath(Path outDir, SootMethodContainer m, String uniq, String ext) {
		Path output = null;
		try {
			StringBuilder sb2 = new StringBuilder();
			String className = m.getDeclaringClass();
			int i3 = className.lastIndexOf('.');
			if(i3 > 0 && className.length() > 1) {
				className = className.substring(i3+1);
			}
			className = className.replace('$', '-');
			sb2.append(FileHelpers.replaceWhitespace(FileHelpers.cleanFileName(className))).append("_");
			String retType = m.getReturnType().toString();
			int i = retType.lastIndexOf('.');
			if(i > 0 && retType.length() > 1) {
				retType = retType.substring(i+1);
			}
			int i2 = retType.lastIndexOf('$');
			if(i2 > 0 && retType.length() > 1) {
				retType = retType.substring(i2+1);
			}
			sb2.append(FileHelpers.replaceWhitespace(FileHelpers.cleanFileName(retType))).append("_");
			sb2.append(FileHelpers.replaceWhitespace(FileHelpers.cleanFileName(m.getName())));
			output = FileHelpers.getPath(outDir, sb2.toString());
			
			StringBuilder sb3 = new StringBuilder();
			sb3.append("_").append(uniq).append(ext);
			output = FileHelpers.getPath(sb3.insert(0, FileHelpers.trimFullFilePath(output.toString(), false, sb3.length())).toString());
		} catch(Throwable t) {
			logger.fatal("{}: Failed to construct the output file for output directory '{}' and method '{}'.",
					t,cn,outDir,m);
			throw new IgnorableRuntimeException();
		}
		return output;
	}
	
	public boolean run() {
		try {
			logger.info("{}: Starting the cross entry points analysis.",cn);
			
			Map<EntryPointNode, Set<EntryPointNode>> allEpsToEps;
			Map<EntryPointNode,Map<EntryPointNode,List<EntryPointNode>>> callerToTargetToPath;
			if(singleHop) {
				allEpsToEps = getDirectlyCalledEpsForEps();
				callerToTargetToPath = null;
			} else {
				callerToTargetToPath = getAllEpsForEps();
				allEpsToEps = new LinkedHashMap<>();
				for(EntryPointNode caller : callerToTargetToPath.keySet())
					allEpsToEps.put(caller, new LinkedHashSet<>(callerToTargetToPath.get(caller).keySet()));
			}
			Map<EntryPointNode, Set<Doublet>> epsToAuthLogic = getEpsToAuthLogic(acminerDB.getValuePairs());
			
			if(reachingGraph && !singleHop) {
				outputGraph(allEpsToEps);
			}
			
			if(wholeGraph && singleHop) {
				outputWholeGraph(allEpsToEps);
			}
			
			if(onlyPerm) {
				epsToAuthLogic = keepOnlyPermDoublet(epsToAuthLogic);
			} else if(onlyPermString) {
				epsToAuthLogic = keepOnlyPermString(epsToAuthLogic);
			}
			
			if(!onlyPerm && !onlyPermString)
				ResultContainer.setComp(new ResultContainer.SortByRatioMissingCheckSizeCallerTarget());
			
			Set<ResultContainer> results = new HashSet<>();
			for(EntryPointNode ep : epsToAuthLogic.keySet()) {
				Set<Doublet> authLogic = epsToAuthLogic.get(ep);
				Set<EntryPointNode> targets = allEpsToEps.get(ep);
				if(targets == null || targets.isEmpty()) {
					results.add(new ResultContainer(ep));
				} else {
					for(EntryPointNode target : targets) {
						Set<Doublet> targetAuthLogic = epsToAuthLogic.get(target);
						Set<Doublet> difference = new HashSet<>(targetAuthLogic);
						difference.removeAll(authLogic);
						double ratio = 0;
						if(!difference.isEmpty())
							ratio = (double)(difference.size()) / (double)(targetAuthLogic.size());
						List<EntryPointNode> path = null;
						if(callerToTargetToPath != null) {
							Map<EntryPointNode,List<EntryPointNode>> targetToPath = callerToTargetToPath.get(ep);
							if(targetToPath != null) {
								path = targetToPath.get(target);
							}
						}
						results.add(new ResultContainer(ep, target, difference, ratio, path));
					}
				}
			}
			
			logger.info("{}: Size of results check 1 {}",cn,results.size());
			
			if(onlyPermString && onlyUserPerm) {
				results = keepOnlyCallersAccessableByThirdParties(results,epsToAuthLogic);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 2 {}",cn,results.size());
			
			if(onlyCallerRes) {
				results = removeAllCallersWithSystemOnlyCallerRestrictions(results);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 3 {}",cn,results.size());
			
			if(onlyRegisteredCallers) {
				results = keepOnlyCallersWithRegisteredServices(results);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 4 {}",cn,results.size());
			
			if(onlyResultsReachingOthers) {
				logger.info("{}: Size of results before results that reach other results {}",cn,results.size());
				results = keepOnlyResultsThatReachOtherResults(results,epsToAuthLogic);
				if(results == null)
					return false;
				logger.info("{}: Size of results after results that reach other results {}",cn,results.size());
			}
			
			logger.info("{}: Size of results check 5 {}",cn,results.size());
			
			results = removeEmptyResults(results);
			if(results == null)
				return false;
			
			logger.info("{}: Size of results check 6 {}",cn,results.size());
			
			if(removeDeputyTargetChecks) {
				results = removeDeputyTargetChecks(results);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 7 {}",cn,results.size());
			
			Map<EntryPointNode,Map<EntryPointNode,Set<SootUnitContainer>>> deputyToTargetToSources = getsourcesForSingleEdgePaths();
			
			if(removeTargetsPartOfChecks) {
				results = removeTargetsUsedInChecks(results,callerToTargetToPath,deputyToTargetToSources);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 8 {}",cn,results.size());
			
			if(singleHop && removeSameCallingId) {
				results = removeAllSameCallingIdentity(results,deputyToTargetToSources);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 9 {}",cn,results.size());
			
			if(removeGlobalSettingsNoise) {
				results = removeGlobalSettingsNoise(results);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 10 {}",cn,results.size());
			
			if(removeSpecialCallersRequired) {
				results = removeIfProtectedBySpecialCallerContextQueries(results);
				if(results == null)
					return false;
				results = removeIfFirstIfIsSystemRestricting(results);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 11 {}",cn,results.size());
			
			if(removeAlreadyHandelingMultiUser) {
				results = removeAlreadyHandelingMultiUser(results);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 12 {}",cn,results.size());
			
			if(removeMultiUserNotNeeded) {
				results = removeMultiUserNotNeeded(results);
				if(results == null)
					return false;
			}
			
			logger.info("{}: Size of results check 13 {}",cn,results.size());
			
			boolean ret = false;
			Map<ResultContainer,GroupContainer> resultToGroup = null;
			results = SortingMethods.sortSet(results);
			if(!toGroup) {
				ret = outResultsNormal(results);
			} else {
				resultToGroup = outResultsGroup(results);
				if(resultToGroup != null)
					ret = true;
			}
			
			if(ret)
				ret = outTSV(results,resultToGroup);
			if(ret)
				ret = outputCallersWithMissingChecks(results);
			if(ret && (onlyPerm || onlyPermString))
				ret = outputCallersWithNoPermissionChecks(results, epsToAuthLogic);
			
			if(ret)
				logger.info("{}: Finished the cross entry points analysis.",cn);
			return ret;
		} catch(Throwable t) {
			logger.fatal("{}: Unexpected error occured during the cross entry points analysis.",t,cn);
			return false;
		}
	}
	
	private Set<ResultContainer> removeMultiUserNotNeeded(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new LinkedHashSet<>();
		Pattern pat = Pattern.compile("(?i)^(?:(?:target|)user(?:id|handle|))$|^uid$");
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode target = r.getTargetEp();
			
			boolean found = false;
			for(Pair<String,String> p : allowedPairs) {
				if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
					ret.add(r);
					found = true;
					break;
				}
			}
			if(found)
				continue;
			
			Set<Doublet> missingChecks = r.getMissingChecks();
			boolean[] tests = {false,false,false,false,false};
			for(Doublet mc : missingChecks) {
				if(mc.toString().equals("`\"android.permission.INTERACT_ACROSS_USERS\"`"))
					tests[0] = true;
				else if(mc.toString().equals("`\"android.permission.INTERACT_ACROSS_USERS_FULL\"`"))
					tests[1] = true;
				else if(mc.toString().equals("`\"android.permission.ACCESS_INSTANT_APPS\"`"))
					tests[2] = true;
				else if(mc.toString().equals("`\"android.permission.VIEW_INSTANT_APPS\"`"))
					tests[3] = true;
				else
					tests[4] = true;
			}
			if(tests[4]) {
				ret.add(r);
			} else if((tests[3] && tests[2] && tests[1] && tests[0]) || (!tests[3] && !tests[2] && (tests[0] || tests[1]))) {
				List<String> argNames = methodToArgNames.get(deputy.getEntryPoint().getSignature());
				found = false;
				for(String argName : argNames) {
					if(pat.matcher(argName).matches()) {
						found = true;
						break;
					}
				}
				if(found)
					ret.add(r);
				else
					removed.add(r);
			} else {
				ret.add(r);
			}
			
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_multi_user_not_needed.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}

	private Set<ResultContainer> removeAlreadyHandelingMultiUser(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new LinkedHashSet<>();
		CallGraph cg = Scene.v().getCallGraph();
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode target = r.getTargetEp();
			
			boolean found = false;
			for(Pair<String,String> p : allowedPairs) {
				if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
					ret.add(r);
					found = true;
					break;
				}
			}
			if(found)
				continue;
			
			Set<Doublet> missingChecks = r.getMissingChecks();
			boolean[] tests = {false,false,false,false,false};
			for(Doublet mc : missingChecks) {
				if(mc.toString().equals("`\"android.permission.INTERACT_ACROSS_USERS\"`"))
					tests[0] = true;
				else if(mc.toString().equals("`\"android.permission.INTERACT_ACROSS_USERS_FULL\"`"))
					tests[1] = true;
				else if(mc.toString().equals("`\"android.permission.ACCESS_INSTANT_APPS\"`"))
					tests[2] = true;
				else if(mc.toString().equals("`\"android.permission.VIEW_INSTANT_APPS\"`"))
					tests[3] = true;
				else
					tests[4] = true;
			}
			if(tests[4]) {
				ret.add(r);
			} else {
				if((tests[3] && tests[2] && tests[1] && tests[0]) || (!tests[3] && !tests[2] && (tests[0] || tests[1]))) {
					EntryPoint ep = deputy.getSootEntryPoint();
					Set<SootMethod> visited = new HashSet<>();
					ArrayDeque<SootMethod> toVisit = new ArrayDeque<>();
					//Assume 1-1 mapping between method and entry point which should be true because Binder methods have been removed
					IExcludeHandler excludeHandler = dataAccessor.getExcludedElementsDB().createNewExcludeHandler(ep);
					toVisit.add(ep.getEntryPoint());
					found = false;
					while(!toVisit.isEmpty()) {
						SootMethod cur = toVisit.poll();
						if(cur.getSignature().equals("<com.android.server.am.ActivityManagerService: int handleIncomingUser(int,int,int,boolean,boolean,java.lang.String,java.lang.String)>")) {
							found = true;
							break;
						}
						if(visited.add(cur) && !excludeHandler.isExcludedMethodWithOverride(cur)) {
							Iterator<Edge> it = cg.edgesOutOf(cur);
							while(it.hasNext()) {
								Edge e = it.next();
								toVisit.add(e.tgt());
							}
						}
					}
					if(found)
						removed.add(r);
					else
						ret.add(r);
				} else {
					ret.add(r);
				}
			}
			
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_handle_multi_user_already.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}
	
	
	private Set<ResultContainer> removeIfFirstIfIsSystemRestricting(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new LinkedHashSet<>();
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode target = r.getTargetEp();
			
			boolean found = false;
			for(Pair<String,String> p : allowedPairs) {
				if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
					ret.add(r);
					found = true;
					break;
				}
			}
			if(found)
				continue;
			
			boolean keep = true;
			Body b = deputy.getEntryPoint().toSootMethod().retrieveActiveBody();
			UnitGraph g = new BriefUnitGraph(b);
			Set<IfStmt> firstIfs = new HashSet<>();
			
			//The first if throws a security exception
			for(Unit u : b.getUnits()) {
				if(u instanceof IfStmt) {
					firstIfs.add((IfStmt)u);
					break;
				}
			}
			
			//Some number of check Preconditions.checkArgument functions occur before the actual first if
			//the others are used as part of this method
			int numOfIf = 0;
			int numOfInvoke = 0;
			for(Unit u : b.getUnits()) {
				if(((Stmt)u).containsInvokeExpr() && 
						((Stmt)u).getInvokeExpr().getMethodRef().getSignature().equals("<com.android.internal.util.Preconditions: void checkArgument(boolean,java.lang.Object)>")) {
					numOfInvoke++;
				} else if(u instanceof IfStmt) {
					if(numOfIf == numOfInvoke) {
						firstIfs.add((IfStmt)u);
						numOfIf++;
					} else {
						break;
					}
				}
			}
			
			
			if(!firstIfs.isEmpty()) {
				boolean hasSE = false;
				for(IfStmt firstIf : firstIfs) {
					IfStmt cur = firstIf;
					while(cur != null) {
						IfStmt next = null;
						for(Unit succ : g.getSuccsOf(cur)) {
							if(succ instanceof DefinitionStmt) {
								Value v = ((DefinitionStmt)succ).getRightOp();
								if(v instanceof NewExpr && ((NewExpr)v).getBaseType().toString().equals("java.lang.SecurityException")) {
									hasSE = true;
									break;
								}
							} else if(succ instanceof IfStmt) {
								next = (IfStmt)succ;
							}
						}
						if(hasSE)
							break;
						else if(next != null)
							cur = next;
						else
							cur = null;
					}
					if(hasSE)
						break;
				}
				if(hasSE)
					keep = false;
			}
			
			if(keep) {
				IfStmt firstIf = null;
				Stmt invokeStmt = null;
				for(Unit u : b.getUnits()) {
					if(u instanceof IfStmt && firstIf == null) {
						firstIf = (IfStmt)u;
					} else if(((Stmt)u).containsInvokeExpr() && 
							((Stmt)u).getInvokeExpr().getMethodRef().getSignature().equals("<com.android.internal.util.Preconditions: void checkArgument(boolean,java.lang.Object)>") && invokeStmt == null) {
						invokeStmt = (Stmt)u;
					}
				}
				if(firstIf != null && invokeStmt != null) {
					Value v = invokeStmt.getInvokeExpr().getArg(0);
					boolean areLinked = false;
					if(v instanceof Local) {
						for(Unit succ : g.getSuccsOf(firstIf)) {
							if(succ instanceof DefinitionStmt && ((DefinitionStmt)succ).getLeftOp().equals(v)) {
								areLinked = true;
							}
						}
					}
					if(areLinked) {
						Value cond = firstIf.getCondition();
						if(cond instanceof BinopExpr) {
							AdvLocalDefs f = new AdvLocalDefs(g,LiveLocals.Factory.newLiveLocals(g));
							List<Value> ops = new ArrayList<>();
							ops.add(((BinopExpr)cond).getOp1());
							ops.add(((BinopExpr)cond).getOp2());
							for(Value op : ops) {
								if(op instanceof Local) {
									for(Unit u : f.getDefsOfAt((Local)op, firstIf)) {
										DefinitionStmt def = ((DefinitionStmt)u);
										if(def.containsInvokeExpr() && def.getInvokeExpr().getMethodRef().name().equals("binderGetCallingUid")) {
											keep = false;
											break;
										}
									}
								}
								if(!keep)
									break;
							}
						}
					}
				}
			}
			
			
			if(keep) {
				ret.add(r);
			} else {
				removed.add(r);
			}
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_if_first_if_is_system_restricting.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}
	
	private Set<ResultContainer> removeIfProtectedBySpecialCallerContextQueries(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new LinkedHashSet<>();
		CallGraph cg = Scene.v().getCallGraph();
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode	target = r.getTargetEp();
			
			boolean found = false;
			for(Pair<String,String> p : allowedPairs) {
				if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
					ret.add(r);
					found = true;
					break;
				}
			}
			if(found)
				continue;
			
			boolean hasSpecialCallerContextQuery = false;
			Pair<Set<String>,Set<String>> p = specialCallerContextQueries.get(deputy.getEntryPoint().getDeclaringClass());
			if(p != null && !p.getSecond().contains(target.getEntryPoint().getSignature())) {
				Set<String> specialCallers = p.getFirst();
				Set<SootMethod> visited = new HashSet<>();
				ArrayDeque<SootMethod> toVisit = new ArrayDeque<>();
				EntryPoint ep = deputy.getSootEntryPoint();
				//Assume 1-1 mapping between method and entry point which should be true because Binder methods have been removed
				IExcludeHandler excludeHandler = dataAccessor.getExcludedElementsDB().createNewExcludeHandler(ep);
				toVisit.add(ep.getEntryPoint());
				while(!toVisit.isEmpty()) {
					SootMethod cur = toVisit.poll();
					if(specialCallers.contains(cur.toString())) {
						hasSpecialCallerContextQuery = true;
						break;
					}
					if(visited.add(cur) && !excludeHandler.isExcludedMethodWithOverride(cur)) {
						Iterator<Edge> it = cg.edgesOutOf(cur);
						while(it.hasNext()) {
							Edge e = it.next();
							toVisit.add(e.tgt());
						}
					}
				}
			}
			
			if(hasSpecialCallerContextQuery) {
				removed.add(r);
			} else {
				ret.add(r);
			}
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_if_protected_by_special_callers.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}

	private Set<ResultContainer> removeEmptyResults(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> noSecondaryEps = new HashSet<>();
		Set<ResultContainer> noMissingChecks = new HashSet<>();
		for(ResultContainer r : results) {
			if(r.isEmptyResult()) {
				noSecondaryEps.add(r);
			} else if(r.getRatio() == 0.0) {
				noMissingChecks.add(r);
			} else {
				ret.add(r);
			}
		}
		
		noSecondaryEps = SortingMethods.sortSet(noSecondaryEps);
		noMissingChecks = SortingMethods.sortSet(noMissingChecks);
		Path noSecondaryEpsPath = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "no_secondary_eps.txt");
		try {
			dumpResultsSet(noSecondaryEps, noSecondaryEpsPath);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,noSecondaryEpsPath);
			return null;
		}
		Path noMissingChecksPath = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "no_missing_checks.txt");
		try {
			dumpResultsSet(noMissingChecks, noMissingChecksPath);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,noMissingChecksPath);
			return null;
		}
		
		return ret;
	}
	
	//TODO the format for single hops needs to be updated to include stubs
	private Set<ResultContainer> keepOnlyResultsThatReachOtherResults(Set<ResultContainer> results, 
			Map<EntryPointNode, Set<Doublet>> epsToAuthLogic) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> singleHopRes = new HashSet<>();
		for(Pair<String,String> p : this.singleHopInput) {
			String callerSig = p.getFirst();
			String targetSig = p.getSecond();
			ResultContainer found = null;
			for(ResultContainer result : results) {
				EntryPointNode caller = result.getCallerEp();
				EntryPointNode target = result.getTargetEp();
				if(caller != null && callerSig.equals(caller.getEntryPoint().getSignature()) 
						&& target != null && targetSig.equals(target.getEntryPoint().getSignature())) {
					found = result;
					break;
				}
			}
			if(found == null) {
				logger.fatal("{}: Could not find a result container for Caller='{}' and Target='{}'",cn,callerSig,targetSig);
				return null;
			}
			singleHopRes.add(found);
		}
		
		for(ResultContainer singleHopResult : singleHopRes) {
			EntryPointNode singleHopCaller = singleHopResult.getCallerEp();
			EntryPointNode singleHopTarget = singleHopResult.getTargetEp();
			for(ResultContainer result : results) {
				if(singleHopCaller.equals(result.getTargetEp())) {
					EntryPointNode caller = result.getCallerEp();
					Set<Doublet> difference = new HashSet<>(epsToAuthLogic.get(singleHopTarget));
					int targetAuthLogicSize = difference.size();
					difference.removeAll(epsToAuthLogic.get(caller));
					double ratio = 0;
					if(!difference.isEmpty())
						ratio = (double)(difference.size()) / (double)(targetAuthLogicSize);
					List<EntryPointNode> path = result.getPath();
					if(path.isEmpty()) {
						path = new ArrayList<>();
						path.add(caller);
						path.add(result.getTargetEp());
					}
					path.add(singleHopTarget);
					ret.add(new ResultContainer(caller, singleHopTarget, difference, ratio, path));
				}
			}
		}
		
		results.removeAll(singleHopRes);
		results.removeAll(ret);
		results = SortingMethods.sortSet(results);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "do_not_reach_single_hops.txt");
		try {
			dumpResultsSet(results, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		return ret;
	}
	
	private Set<ResultContainer> keepOnlyCallersWithRegisteredServices(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new LinkedHashSet<>();
		for(ResultContainer r : results) {
			if(registeredServices.contains(r.getCallerEp().getEntryPoint().getDeclaringClass()))
				ret.add(r);
			else
				removed.add(r);
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "callers_in_unregistered_services.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		return ret;
	}
	
	private Set<ResultContainer> removeAllCallersWithSystemOnlyCallerRestrictions(Set<ResultContainer> results) {
		Set<ResultContainer> newResults = new LinkedHashSet<>();
		Set<ResultContainer> oldResults = new LinkedHashSet<>();
		for(ResultContainer r : results) {
			if(!onlyCallerRestrictions.hasOnlyCallerRestriction(r.getCallerEp().getEntryPoint().getSignature()))
				newResults.add(r);
			else
				oldResults.add(r);
		}
		
		oldResults = SortingMethods.sortSet(oldResults);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "callers_with_system_restrictions.txt");
		try {
			dumpResultsSet(oldResults, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		return newResults;
	}
	
	private Set<ResultContainer> removeGlobalSettingsNoise(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new LinkedHashSet<>();
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode	target = r.getTargetEp();
			
			boolean found = false;
			for(Pair<String,String> p : allowedPairs) {
				if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
					ret.add(r);
					found = true;
					break;
				}
			}
			if(found)
				continue;
			
			if(target.getEntryPoint().getSignature().equals("<com.android.server.locksettings.LockSettingsService: java.lang.String getString(java.lang.String,java.lang.String,int)>")) {
				removed.add(r);
			} else {
				ret.add(r);
			}
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_global_settings_noise.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}
	
	private Set<ResultContainer> removeDeputyTargetChecks(Set<ResultContainer> results) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new LinkedHashSet<>();
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode	target = r.getTargetEp();
			
			if(cqdb.isContextQuery(deputy.getEntryPoint().toSootMethod()) || cqdb.isContextQuery(target.getEntryPoint().toSootMethod())) {
				boolean found = false;
				for(Pair<String,String> p : allowedPairs) {
					if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
						ret.add(r);
						found = true;
						break;
					}
				}
				if(!found)
					removed.add(r);
			} else {
				ret.add(r);
			}
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_paths_deputy_target_are_checks.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}
	
	private boolean testIfKnownVulnWereRemoved(Set<ResultContainer> removed) {
		if(testIfKnownVuln) {
			boolean allFine = true;
			for(ResultContainer r : removed) {
				String deputy = r.getCallerEp().getEntryPoint().getSignature();
				String target = r.getTargetEp().getEntryPoint().getSignature();
				for(Pair<String,String> p : knownVulnPaths) {
					if(deputy.equals(p.getFirst()) && target.equals(p.getSecond())) {
						logger.fatal("{}: Removed known vuln {} --> {}",cn,deputy,target);
						allFine = false;
						break;
					}
				}
			}
			return allFine;
		}
		return true;
	}

	private Set<ResultContainer> keepOnlyCallersAccessableByThirdParties(Set<ResultContainer> results, Map<EntryPointNode, Set<Doublet>> epsToAuthLogic) {
		Set<String> allowedProtectionLevels = ImmutableSet.of("normal","dangerous","instant","runtime","pre23");
		Set<ResultContainer> newResults = new LinkedHashSet<>();
		Set<ResultContainer> oldResults = new LinkedHashSet<>();
		Pattern p = Pattern.compile("^`\"([^`\"]+)\"`$");
		for(ResultContainer r : results) {
			EntryPointNode caller = r.getCallerEp();
			Set<Doublet> authLogic = epsToAuthLogic.get(caller);
			boolean hasSystemPermission = false;
			for(Doublet d : authLogic) {
				String perm = d.toString();
				Matcher m = p.matcher(perm);
				if(m.matches())
					perm = m.group(1);
				Permission permission = systemAndroidManifest.getPermission(perm);
				if(permission != null) {
					boolean hasUserProtectionLevel = false;
					Set<String> protectionLevels = permission.getProtectionLevels();
					for(String s : allowedProtectionLevels) {
						if(protectionLevels.contains(s))
							hasUserProtectionLevel = true;
					}
					if(!hasUserProtectionLevel) {
						hasSystemPermission = true;
						break;
					}
				} else if(perm.equals("com.android.printspooler.permission.ACCESS_ALL_PRINT_JOBS")) {
					//Not defined in the system android manifest but in the app itself?
					//Defined as signature in Android 8.0.1
					//Used in the PrintManagerService
					hasSystemPermission = true;
					break;
				}
			}
			if(!hasSystemPermission) {
				newResults.add(r);
			} else {
				oldResults.add(r);
			}
		}
		
		oldResults = SortingMethods.sortSet(oldResults);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "callers_with_system_permissions.txt");
		try {
			dumpResultsSet(oldResults, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		return newResults;
	}
	
	private Map<EntryPointNode, Set<Doublet>> getEpsToAuthLogic(
			Map<SootClassContainer, Map<SootMethodContainer, Set<Doublet>>> stubToEpsToAuthLogic) {
		Map<EntryPointNode, Set<Doublet>> ret = new HashMap<>();
		for(SootClassContainer stub : stubToEpsToAuthLogic.keySet()) {
			Map<SootMethodContainer, Set<Doublet>> epToAuthLogic = stubToEpsToAuthLogic.get(stub);
			for(SootMethodContainer ep : epToAuthLogic.keySet()) {
				ret.put(new EntryPointNode(ep,stub), epToAuthLogic.get(ep));
			}
		}
		for(EntryPointNode ep : ret.keySet()) {
			ret.put(ep, SortingMethods.sortSet(ret.get(ep)));
		}
		return SortingMethods.sortMapKeyAscending(ret);
	}
	
	private Map<EntryPointNode, Set<EntryPointNode>> getDirectlyCalledEpsForEps() {
		Map<EntryPointNode, Set<EntryPointNode>> ret = new LinkedHashMap<>();
		for(EntryPointContainer epContainer : ieepsDB.getOutputData()) {
			SootMethodContainer ep = epContainer.getEntryPointContainer();
			SootClassContainer stub = epContainer.getStubContainer();
			Set<EntryPointNode> temp;
			if(ep.getDeclaringClass().equals("android.os.Binder")) { //Remove all binder methods because they are noise
				temp = Collections.emptySet();
			} else {
				temp = new LinkedHashSet<>();
				for(EntryPointEdge other : epContainer.getReferenceEntryPointContainers()) {
					SootMethodContainer otherM = other.getReferencedEntryPointContainer();
					SootClassContainer otherC = other.getReferencedStubContainer();
					if(!otherM.getDeclaringClass().equals("android.os.Binder"))
						temp.add(new EntryPointNode(otherM,otherC));
				}
			}
			ret.put(new EntryPointNode(ep,stub), temp);
		}
		return ret;
	}
	
	private Map<EntryPointNode,Map<EntryPointNode,Set<SootUnitContainer>>> getsourcesForSingleEdgePaths() {
		Map<EntryPointNode,Map<EntryPointNode,Set<SootUnitContainer>>> deputyToTargetToSources = new HashMap<>();
		for(EntryPointContainer epContainer : ieepsDB.getOutputData()) {
			Map<EntryPointNode,Set<SootUnitContainer>> targetToSources = new HashMap<>();
			deputyToTargetToSources.put(new EntryPointNode(epContainer.getEntryPointContainer(),epContainer.getStubContainer()), targetToSources);
			for(EntryPointEdge other : epContainer.getReferenceEntryPointContainers()) {
				EntryPointNode tgt = new EntryPointNode(other.getReferencedEntryPointContainer(),other.getReferencedStubContainer());
				for(SourceContainer sourceC : other.getSourceContainers()) {
					Set<SootUnitContainer> sources = targetToSources.get(tgt);
					if(sources == null) {
						sources = new HashSet<>();
						targetToSources.put(tgt, sources);
					}
					sources.addAll(sourceC.getUnitContainers());
				}
			}
		}
		return deputyToTargetToSources;
	}
	
	//Only called during the single hops stage
	private Set<ResultContainer> removeAllSameCallingIdentity(Set<ResultContainer> results, 
			Map<EntryPointNode,Map<EntryPointNode,Set<SootUnitContainer>>> deputyToTargetToSources) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new HashSet<>();
		CallGraph cg = Scene.v().getCallGraph();
		Map<SootMethod,FastDominatorsFinder<Unit>> dominatorsCache = new HashMap<>();
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode target = r.getTargetEp();
			
			boolean found = false;
			for(Pair<String,String> p : allowedPairs) {
				if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
					ret.add(r);
					found = true;
					break;
				}
			}
			if(found)
				continue;
			
			Set<SootUnitContainer> sources = deputyToTargetToSources.get(deputy).get(target);
			String dc = deputy.getEntryPoint().getDeclaringClass();
			String tc = target.getEntryPoint().getDeclaringClass();
			
			boolean hasDirectReferenceToTargetService = false;
			for(SootUnitContainer source : sources) {
				if(((Stmt)source.toUnit()).getInvokeExpr().getMethodRef().declaringClass().toString().equals(tc)) {
					hasDirectReferenceToTargetService = true;
					break;
				}
			}
			
			if(hasDirectReferenceToTargetService || dc.equals(tc) || (dc.startsWith(tc) && !dc.replace(tc + "$", "").contains("$"))) {
				EntryPoint ep = deputy.getSootEntryPoint();
				//Assume 1-1 mapping between method and entry point which should be true because Binder methods have been removed
				IExcludeHandler excludeHandler = dataAccessor.getExcludedElementsDB().createNewExcludeHandler(ep);;
				ExcludingEdgePredicate edgePred = new ExcludingEdgePredicate(cg,excludeHandler);
				boolean allSourcesInSameContext = true;
				for(SootUnitContainer source : sources) {
					SootMethod sourceMethod = source.getSource().toSootMethod();
					Unit sourceUnit = source.toUnit();
					Set<Unit> dominators = new HashSet<>();
					ArrayDeque<Pair<Unit,SootMethod>> queue = new ArrayDeque<>();
					Set<Pair<Unit,SootMethod>> seen = new HashSet<>();
					queue.add(new Pair<>(sourceUnit,sourceMethod));
					while(!queue.isEmpty()) {
						Pair<Unit,SootMethod> p = queue.poll();
						Unit unit = p.getFirst();
						SootMethod method = p.getSecond();
						FastDominatorsFinder<Unit> f = dominatorsCache.get(method);
						if(f == null) {
							f = new FastDominatorsFinder<>(new ExceptionalUnitGraph(method.retrieveActiveBody()));
							dominatorsCache.put(method, f);
						}
						dominators.addAll(f.getDominatorsSet(unit));
						
						if(!method.equals(ep.getEntryPoint())) {
							Iterator<Edge> it = cg.edgesInto(method);
							while(it.hasNext()) {
								Edge e = it.next();
								if(edgePred.want(e)) {
									Pair<Unit,SootMethod> newP = new Pair<>(e.srcUnit(),e.src());
									if(seen.add(newP) && !queue.contains(newP)) {
										queue.add(newP);
									}
								}
							}
						}
					}
					
					boolean clearsCallingId = false;
					boolean restoresCallingId = false;
					for(Unit u : dominators) {
						if(((Stmt)u).containsInvokeExpr()) {
							SootMethodRef ref = ((Stmt)u).getInvokeExpr().getMethodRef();
							String name = ref.name();
							String sc = ref.declaringClass().toString();
							if((name.equals("clearCallingIdentity") && sc.equals("android.os.Binder")) 
								|| (name.equals("binderClearCallingIdentity") 
									&& sc.equals("com.android.server.devicepolicy.DevicePolicyManagerService$Injector"))
								|| (name.equals("injectClearCallingIdentity") 
										&& sc.equals("com.android.server.pm.LauncherAppsService$LauncherAppsImpl"))
								|| (name.equals("injectClearCallingIdentity")
										&& sc.equals("com.android.server.pm.ShortcutService"))
							) {
								clearsCallingId = true;
							} else if((name.equals("restoreCallingIdentity") && sc.toString().equals("android.os.Binder"))
								|| (name.equals("binderRestoreCallingIdentity") 
									&& sc.equals("com.android.server.devicepolicy.DevicePolicyManagerService$Injector"))
								|| (name.equals("injectRestoreCallingIdentity") 
										&& sc.equals("com.android.server.pm.LauncherAppsService$LauncherAppsImpl"))
								|| (name.equals("injectRestoreCallingIdentity")
										&& sc.equals("com.android.server.pm.ShortcutService"))
							) {
								restoresCallingId = true;
							}
						}
					}
					
					if(clearsCallingId != restoresCallingId)
						allSourcesInSameContext = false;
				}
				
				if(allSourcesInSameContext) {
					removed.add(r);
				} else {
					ret.add(r);
				}
				
			} else {
				ret.add(r);
			}
			
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_paths_with_same_calling_id.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}
	
	private Set<ResultContainer> removeTargetsUsedInChecks(Set<ResultContainer> results, 
			Map<EntryPointNode,Map<EntryPointNode,List<EntryPointNode>>> deputyToTargetToPath,
			Map<EntryPointNode,Map<EntryPointNode,Set<SootUnitContainer>>> deputyToTargetToSources) {
		Set<ResultContainer> ret = new LinkedHashSet<>();
		Set<ResultContainer> removed = new HashSet<>();
		for(ResultContainer r : results) {
			EntryPointNode deputy = r.getCallerEp();
			EntryPointNode target = r.getTargetEp();
			EntryPointNode targetCaller = null;
			
			boolean found = false;
			for(Pair<String,String> p : allowedPairs) {
				if(p.getFirst().equals(deputy.getEntryPoint().getSignature()) && p.getSecond().equals(target.getEntryPoint().getSignature())) {
					ret.add(r);
					found = true;
					break;
				}
			}
			if(found)
				continue;
			
			if(deputyToTargetToPath != null) {
				List<EntryPointNode> path = deputyToTargetToPath.get(deputy).get(target);
				targetCaller = path.get(path.size()-2);
			} else {
				targetCaller = deputy;
			}
			Set<SootUnitContainer> sources = deputyToTargetToSources.get(targetCaller).get(target);
			Map<SootMethod,Set<SootMethod>> contextQueriesToSubGraphMethods = cqdb.getContextQueriesWithSubGraphMethods(targetCaller.getSootEntryPoint());
			Set<SootMethodContainer> sourceMethods = new HashSet<>();
			Set<SootMethod> sourcesNotInContextQueries = new HashSet<>();
			for(SootUnitContainer u : sources) {
				if(sourceMethods.add(u.getSource())) {
					SootMethod sourceMethod = u.getSource().toSootMethod();
					found = false;
					for(SootMethod cq : contextQueriesToSubGraphMethods.keySet()) {
						//The callsite of the target is in a CQ method body or the sub graph of the CQ
						if(cq.equals(sourceMethod) || contextQueriesToSubGraphMethods.get(cq).contains(sourceMethod)) { 
							found = true;
							break;
						} 
					}
					if(!found)
						sourcesNotInContextQueries.add(sourceMethod);
				}
			}
			if(sourcesNotInContextQueries.isEmpty()) {
				removed.add(r);
			} else {
				ret.add(r);
			}
		}
		
		removed = SortingMethods.sortSet(removed);
		Path out = FileHelpers.getPath(config.getFilePath("debug_arf-dir"), "removed_paths_target_part_of_checks.txt");
		try {
			dumpResultsSet(removed, out);
		} catch(Throwable t) {
			logger.fatal("{}: Failed to output file '{}'",t,cn,out);
			return null;
		}
		
		if(testIfKnownVulnWereRemoved(removed))
			return ret;
		return null;
	}
	
	private Map<EntryPointNode, Map<EntryPointNode,List<EntryPointNode>>> getAllEpsForEps() {
		Map<EntryPointNode, Set<EntryPointNode>> directEps = getDirectlyCalledEpsForEps();
		Map<EntryPointNode,Map<EntryPointNode,List<EntryPointNode>>> callerToTargetToPath = new LinkedHashMap<>();
		for(EntryPointNode ep : directEps.keySet()) {
			ArrayDeque<EntryPointNode> toVisit = new ArrayDeque<>();
			ArrayDeque<List<EntryPointNode>> toVisitPaths = new ArrayDeque<>();
			Map<EntryPointNode,List<EntryPointNode>> targetToPath = new HashMap<>();
			toVisit.add(ep);
			toVisitPaths.add(ImmutableList.of(ep));
			while(!toVisit.isEmpty()) {
				EntryPointNode cur = toVisit.poll();
				List<EntryPointNode> path = toVisitPaths.poll();
				if(!targetToPath.containsKey(cur)) {
					targetToPath.put(cur, path);
					Set<EntryPointNode> children = directEps.get(cur);
					if(children != null && !children.isEmpty()) {
						for(EntryPointNode other : children) {
							toVisit.add(other);
							toVisitPaths.add(ImmutableList.<EntryPointNode>builder().addAll(path).add(other).build());
						}
					}
				}
			}
			targetToPath.remove(ep);
			callerToTargetToPath.put(ep, SortingMethods.sortMapKeyAscending(targetToPath));
		}
		return callerToTargetToPath;
	}
	
	private void dumpResultsSet(Set<ResultContainer> results, Path out) throws Exception {
		try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(out))) {
			ps.println("Size: " + results.size());
			for(ResultContainer r : results) {
				ps.println(r);
			}
		}
	}
	
}

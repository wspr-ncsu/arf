package org.sag.arf;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import org.sag.acminer.IACMinerDataAccessor;
import org.sag.common.io.FileHash;
import org.sag.main.config.PhaseConfig;
import org.sag.main.phase.AbstractPhaseHandler;
import org.sag.main.phase.IPhaseHandler;
import org.sag.sootinit.IPASootLoader;

public class ARFHandler  extends AbstractPhaseHandler {
	
	public static final String optPerm = "Perm";
	public static final String optPermString = "PermString";
	public static final String optGroup = "Group";
	public static final String optOnlyUserPerm = "OnlyUserPerm";
	public static final String optOnlyCallerRes = "OnlyCallerRes";
	public static final String optReachingGraph = "ReachingGraph";
	public static final String optSingleHop = "SingleHop";
	public static final String optOnlyRegisteredCallers = "OnlyRegisteredCallers";
	public static final String optOnlyResultsReachingOthers = "OnlyResultsReachingOthers";
	public static final String optRemoveDeputyTargetChecks = "RemoveDeputyTargetChecks";
	public static final String optTestIfKnownVuln = "TestIfKnownVuln";
	public static final String optRemoveTargetsPartOfChecks = "RemoveTargetsPartOfChecks";
	public static final String optRemoveSameCallingId = "RemoveSameCallingId";
	public static final String optRemoveGlobalSettingsNoise = "RemoveGlobalSettingsNoise";
	public static final String optRemoveSpecialCallersRequired = "RemoveSpecialCallersRequired";
	public static final String optRemoveAlreadyHandelingMultiUser = "RemoveAlreadyHandelingMultiUser";
	public static final String optRemoveMultiUserNotNeeded = "RemoveMultiUserNotNeeded";
	public static final String optWholeGraph = "WholeGraph";
	
	private Path jimpleJar;
	
	public ARFHandler(List<IPhaseHandler> depPhases, PhaseConfig pc) {
		super(depPhases, pc);
	}
	
	@Override
	protected void initInner() {
		this.jimpleJar = dependencyFilePaths.get(0);
		
	}
	
	@Override
	protected List<FileHash> getOldDependencyFileHashes() throws Exception {
		return Collections.emptyList();
	}

	@Override
	protected void loadExistingInformation() throws Exception {}

	@Override
	protected boolean isSootInitilized() {
		return IPASootLoader.v().isSootLoaded();
	}

	@Override
	protected boolean initilizeSoot() {
		return IPASootLoader.v().load(((IACMinerDataAccessor)dataAccessor), jimpleJar, ai.getJavaVersion(), logger);
	}
	
	@Override
	protected boolean doWork() {
		try {
			ARFAnalysis analysis = new ARFAnalysis((IACMinerDataAccessor)dataAccessor, this, logger);
			if(!analysis.init() || !analysis.run()) {
				logger.fatal("{}: Encountered errors during executation.",cn);
				return false;
			}
		} catch(Throwable t) {
			logger.fatal("{}: Unexpected exception during the run.",t,cn);
			return false;
		}
		return true;
	}
	
	//Hardcode in forced run so that if the phase is enabled it is always run without looking at anything else
	@Override
	public boolean isForcedRun(){
		return true;
	}

}

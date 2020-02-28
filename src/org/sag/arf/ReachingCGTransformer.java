package org.sag.arf;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.sag.acminer.database.entrypointedges.EntryPointContainer;
import org.sag.acminer.database.entrypointedges.EntryPointEdge;
import org.sag.acminer.database.entrypointedges.IEntryPointEdgesDatabase;
import org.sag.acminer.database.entrypointedges.SourceContainer;
import org.sag.common.graphtools.AlEdge;
import org.sag.common.graphtools.AlElement.Color;
import org.sag.common.graphtools.AlNode;
import org.sag.common.graphtools.AlNode.Shape;
import org.sag.common.tools.SortingMethods;
import org.sag.common.graphtools.Transformer;
import org.sag.common.tuple.Pair;
import org.sag.soot.xstream.SootClassContainer;
import org.sag.soot.xstream.SootMethodContainer;

import com.google.common.collect.ImmutableSet;

public class ReachingCGTransformer extends Transformer<EntryPointNode> {
	
	private final IEntryPointEdgesDatabase db;
	private final Map<EntryPointNode,Map<EntryPointNode,Set<SootMethodContainer>>> callerToCalleeEdges;
	private volatile Map<EntryPointNode, AlNode> methodToNode;
	private volatile Map<Pair<EntryPointNode,EntryPointNode>,AlEdge> pairToEdge;
	private volatile Map<EntryPointNode,Long> epToIndexToExtraData;
	
	public ReachingCGTransformer(IEntryPointEdgesDatabase db) {
		super();
		Objects.requireNonNull(db);
		this.db = db;
		this.callerToCalleeEdges = getDirectlyCalledEpsForEps();
	}
	
	public IEntryPointEdgesDatabase getEntryPointEdgesDatabase() {
		return db;
	}
	
	@Override
	public Map<EntryPointNode, AlNode> getNodeToGraphNodeMap() {
		return methodToNode;
	}

	@Override
	public Map<Pair<EntryPointNode, EntryPointNode>, AlEdge> getEdgeToGraphEdgeMap() {
		return pairToEdge;
	}
	
	public Map<EntryPointNode,Map<EntryPointNode,Set<SootMethodContainer>>> getCallerToCalleeEdges() {
		return callerToCalleeEdges;
	}

	@Override
	public void transform() {
		this.methodToNode = new HashMap<>();
		this.pairToEdge = new HashMap<>();
		this.epToIndexToExtraData = new HashMap<>();
		for(EntryPointNode caller : callerToCalleeEdges.keySet()) {
			Map<EntryPointNode,Set<SootMethodContainer>> callees = callerToCalleeEdges.get(caller);
			if(callees == null || callees.isEmpty()) {
				if(!methodToNode.containsKey(caller))
					methodToNode.put(caller, new AlNode(nextId(),caller.toString()));
			} else {
				for(EntryPointNode callee : callees.keySet()) {
					Pair<EntryPointNode,EntryPointNode> edge = new Pair<>(caller,callee);
					AlEdge graphEdge = pairToEdge.get(edge);
					if(graphEdge == null) {
						AlNode callerGraphNode = methodToNode.get(caller);
						if(callerGraphNode == null) {
							callerGraphNode = new AlNode(nextId(),caller.toString());
							methodToNode.put(caller, callerGraphNode);
						}
						AlNode calleeGraphNode;
						if(caller.equals(callee)) {
							calleeGraphNode = callerGraphNode;
						} else {
							calleeGraphNode = methodToNode.get(callee);
							if(calleeGraphNode == null) {
								calleeGraphNode = new AlNode(nextId(),callee.toString());
								methodToNode.put(callee, calleeGraphNode);
							}
						}
						graphEdge = new AlEdge(nextId(), callerGraphNode, calleeGraphNode);
						pairToEdge.put(edge, graphEdge);
					} else {
						graphEdge.incWeight();
					}
				}
			}
		}
	}
	
	public long getExtraDataIndex(EntryPointNode ep) {
		if(epToIndexToExtraData != null) {
			Long l = epToIndexToExtraData.get(ep);
			if(l != null)
				return l;
		}
		return -1;
	}
	
	public void setExtraDataToCallSources() {
		for(EntryPointNode ep : callerToCalleeEdges.keySet()) {
			ArrayDeque<EntryPointNode> toVisit = new ArrayDeque<>();
			Set<EntryPointNode> visited = new HashSet<>();
			Map<EntryPointNode,Set<SootMethodContainer>> methodsToExtraData = new HashMap<>();
			toVisit.add(ep);
			while(!toVisit.isEmpty()) {
				EntryPointNode caller = toVisit.poll();
				if(visited.add(caller)) {
					Map<EntryPointNode,Set<SootMethodContainer>> children = callerToCalleeEdges.get(caller);
					if(children != null && !children.isEmpty()) {
						for(EntryPointNode callee : children.keySet()) {
							Set<SootMethodContainer> sources = children.get(callee);
							Set<SootMethodContainer> temp = methodsToExtraData.get(callee);
							if(temp == null) {
								temp = new HashSet<>();
								methodsToExtraData.put(callee, temp);
							}
							temp.addAll(sources);
							toVisit.add(callee);
						}
					}
				}
			}
			
			Map<EntryPointNode,String> mToE = new HashMap<>();
			for(EntryPointNode m : methodsToExtraData.keySet()) {
				StringBuilder sb = new StringBuilder();
				boolean fs = true;
				for(SootMethodContainer source: SortingMethods.sortSet(methodsToExtraData.get(m))) {
					if(fs)
						fs = false;
					else
						sb.append("\n");
					sb.append(source.getSignature());
				}
				mToE.put(m, sb.toString());
			}
			mToE = SortingMethods.sortMapKeyAscending(mToE);
			epToIndexToExtraData.put(ep, applyExtraDataToNodes(mToE));
		}
	}
	
	private Map<EntryPointNode, Map<EntryPointNode, Set<SootMethodContainer>>> getDirectlyCalledEpsForEps() {
		Map<EntryPointNode, Map<EntryPointNode,Set<SootMethodContainer>>> ret = new LinkedHashMap<>();
		Set<String> removeSigs = ImmutableSet.of(
			"<com.android.server.am.ActivityManagerService: int checkPermission(java.lang.String,int,int)>",
			"<com.android.server.am.ActivityManagerService: int checkPermissionWithToken(java.lang.String,int,int,android.os.IBinder)>",
			"<com.android.server.pm.PackageManagerService: int checkPermission(java.lang.String,java.lang.String,int)>",
			"<com.android.server.pm.PackageManagerService: int checkUidPermission(java.lang.String,int)>",
			"<com.android.server.am.ActivityManagerService$PermissionController: boolean checkPermission(java.lang.String,int,int)>",
			"<android.os.Binder: void dump(java.io.FileDescriptor,java.lang.String[])>" //Because this one has too much noise
		);
		for(EntryPointContainer epContainer : db.getOutputData()) {
			SootMethodContainer ep = epContainer.getEntryPointContainer();
			SootClassContainer stub = epContainer.getStubContainer();
			EntryPointNode caller = new EntryPointNode(ep, stub);
			Map<EntryPointNode,Set<SootMethodContainer>> calleesToSources;
			if(removeSigs.contains(ep.getSignature())) {
				calleesToSources = Collections.emptyMap();
			} else {
				calleesToSources = new LinkedHashMap<>();
				for(EntryPointEdge callee : epContainer.getReferenceEntryPointContainers()) {
					SootMethodContainer calleeM = callee.getReferencedEntryPointContainer();
					SootClassContainer calleeC = callee.getReferencedStubContainer();
					if(!removeSigs.contains(calleeM.getSignature())) {
						EntryPointNode calleeNode = new EntryPointNode(calleeM,calleeC);
						Set<SootMethodContainer> calleeSourcesFromCaller = calleesToSources.get(calleeNode);
						if(calleeSourcesFromCaller == null) {
							calleeSourcesFromCaller = new HashSet<>();
							calleesToSources.put(calleeNode, calleeSourcesFromCaller);
						}
						for(SourceContainer s : callee.getSourceContainers()) {
							calleeSourcesFromCaller.add(s.getSourceContainer());
						}
					}
				}
			}
			ret.put(caller, calleesToSources);
		}
		for(EntryPointNode caller : ret.keySet()) {
			Map<EntryPointNode,Set<SootMethodContainer>> calleeToSources = ret.get(caller);
			for(EntryPointNode callee : calleeToSources.keySet()) {
				calleeToSources.put(callee, SortingMethods.sortSet(calleeToSources.get(callee)));
			}
			ret.put(caller, SortingMethods.sortMapKeyAscending(calleeToSources));
		}
		return SortingMethods.sortMapKeyAscending(ret);
	}

	@Override
	public long applyColorsToNodes(Map<EntryPointNode, List<Color>> colorMap) {
		Objects.requireNonNull(colorMap);
		long ret = nextNodeColorIndex();
		for(EntryPointNode m : colorMap.keySet()) {
			AlNode node = methodToNode.get(m);
			if(node != null) {
				node.setColors(ret, colorMap.get(m));
			}
		}
		return ret;
	}

	@Override
	public long applyColorsToEdges(Map<Pair<EntryPointNode, EntryPointNode>, Color> colorMap) {
		Objects.requireNonNull(colorMap);
		long ret = nextEdgeColorIndex();
		for(Pair<EntryPointNode,EntryPointNode> e : colorMap.keySet()) {
			AlEdge edge = pairToEdge.get(e);
			if(edge != null) {
				edge.setColor(ret, colorMap.get(e));
			}
		}
		return ret;
	}

	@Override
	public long applyShapesToNodes(Map<EntryPointNode, Shape> shapeMap) {
		Objects.requireNonNull(shapeMap);
		long ret = nextNodeShapeIndex();
		for(EntryPointNode m : shapeMap.keySet()) {
			AlNode node = methodToNode.get(m);
			if(node != null) {
				node.setShape(ret, shapeMap.get(m));
			}
		}
		return ret;
	}
	
	@Override
	public long applyExtraDataToNodes(Map<EntryPointNode, String> extraDataMap) {
		Objects.requireNonNull(extraDataMap);
		long ret = nextNodeExtraDataIndex();
		for(EntryPointNode m : extraDataMap.keySet()) {
			AlNode node = methodToNode.get(m);
			if(node != null)
				node.setExtraData(ret, extraDataMap.get(m));
		}
		return ret;
	}

}

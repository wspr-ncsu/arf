package org.sag.arf;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;

import org.sag.common.graphtools.AlEdge;
import org.sag.common.graphtools.AlNode;
import org.sag.common.graphtools.Formatter;
import org.sag.common.tuple.Pair;
import org.sag.soot.xstream.SootMethodContainer;

public class ReachingCGFormatter extends Formatter {
	
	protected final int depth;
	protected final EntryPointNode ep;
	protected final Collection<AlNode> nodes;
	protected final Collection<AlEdge> edges;
	protected final ReachingCGTransformer trans;
	
	public ReachingCGFormatter(EntryPointNode ep, ReachingCGTransformer trans, int depth, long nodeColorIndex, Path outputPath) {
		this(ep,trans,depth,nodeColorIndex,-1,-1,-1,outputPath);
	}
	
	public ReachingCGFormatter(EntryPointNode ep, ReachingCGTransformer trans, int depth, long nodeColorIndex, long nodeExtraDataIndex, Path outputPath) {
		this(ep,trans,depth,nodeColorIndex,-1,-1,nodeExtraDataIndex,outputPath);
	}
	
	public ReachingCGFormatter(EntryPointNode ep, ReachingCGTransformer trans, int depth, long nodeColorIndex, long nodeShapeIndex, 
			long edgeColorIndex, long nodeExtraDataIndex, Path outputPath) {
		super(nodeColorIndex,nodeShapeIndex,edgeColorIndex,nodeExtraDataIndex,outputPath);
		this.depth = depth;
		this.trans = trans;
		this.ep = ep;
		this.nodes = new TreeSet<AlNode>();
		this.edges = new TreeSet<AlEdge>();
	}
	
	@Override
	public Collection<AlNode> getNodes(){
		return nodes;
	}
	
	@Override
	public Collection<AlEdge> getEdges(){
		return edges;
	}
	
	@Override
	public String getComment() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.getComment());
		sb.append("  Type: Reaching Entry Points Graph\n");
		sb.append("  Entry Point: ").append(ep.toString()).append("\n");
		return sb.toString();
	}
	
	@Override
	public void format() {
		Map<EntryPointNode,AlNode> methodToNode = trans.getNodeToGraphNodeMap();
		Map<Pair<EntryPointNode,EntryPointNode>,AlEdge> pairToEdge = trans.getEdgeToGraphEdgeMap();
		Map<EntryPointNode, Map<EntryPointNode,Set<SootMethodContainer>>> directEps = trans.getCallerToCalleeEdges();
		ArrayDeque<EntryPointNode> toVisit = new ArrayDeque<>();
		Queue<Integer> depthCount = new ArrayDeque<Integer>();
		Set<EntryPointNode> visited = new HashSet<>();
		toVisit.add(ep);
		depthCount.add(1);
		nodes.add(methodToNode.get(ep));
		while(!toVisit.isEmpty()) {
			EntryPointNode caller = toVisit.poll();
			int curDepth = depthCount.poll();
			visited.add(caller);
			if(depth == 0 || curDepth < depth) {
				Map<EntryPointNode,Set<SootMethodContainer>> children = directEps.get(caller);
				if(children != null && !children.isEmpty()) {
					for(EntryPointNode callee : children.keySet()) {
						edges.add(pairToEdge.get(new Pair<>(caller,callee)));
						if(!caller.equals(callee) && !visited.contains(callee) && !toVisit.contains(callee)) {
							nodes.add(methodToNode.get(callee));
							toVisit.add(callee);
							depthCount.add(curDepth+1);
						}
					}
				}
			}
		}
	}

}

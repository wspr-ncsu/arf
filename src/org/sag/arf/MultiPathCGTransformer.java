package org.sag.arf;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.sag.common.graphtools.AlEdge;
import org.sag.common.graphtools.AlElement.Color;
import org.sag.common.graphtools.AlNode;
import org.sag.common.graphtools.AlNode.Shape;
import org.sag.common.graphtools.Transformer;
import org.sag.common.tuple.Pair;

public class MultiPathCGTransformer extends Transformer<EntryPointNode> {
	
	private volatile Map<EntryPointNode, AlNode> methodToNode;
	private volatile Map<Pair<EntryPointNode,EntryPointNode>,AlEdge> pairToEdge;
	private final Map<EntryPointNode, Set<EntryPointNode>> directlyCalledEpsForEps;
	
	public MultiPathCGTransformer(Map<EntryPointNode, Set<EntryPointNode>> directlyCalledEpsForEps) {
		super();
		this.directlyCalledEpsForEps = directlyCalledEpsForEps;
	}
	
	@Override
	public Map<EntryPointNode, AlNode> getNodeToGraphNodeMap() {
		return methodToNode;
	}

	
	public Collection<AlNode> getNodes() {
		return new TreeSet<AlNode>(methodToNode.values());
	}

	@Override
	public Map<Pair<EntryPointNode, EntryPointNode>, AlEdge> getEdgeToGraphEdgeMap() {
		return pairToEdge;
	}
	
	public Collection<AlEdge> getEdges() {
		return new TreeSet<AlEdge>(pairToEdge.values());
	}
	
	public long applyDefaultColorMap() {
		Map<EntryPointNode,List<Color>> ret = new HashMap<>();
		for(EntryPointNode method : methodToNode.keySet()) {
			ret.put(method, Collections.singletonList(Color.YELLOW));
		}
		return applyColorsToNodes(ret);
	}
	
	public long applyDefaultShapeMap() {
		Map<EntryPointNode,Shape> ret = new HashMap<>();
		for(EntryPointNode method : methodToNode.keySet()) {
			ret.put(method, Shape.ELLIPSE);
		}
		return applyShapesToNodes(ret);
	}
	
	@Override
	public void transform() {
		this.methodToNode = new HashMap<>();
		this.pairToEdge = new HashMap<>();
		for(EntryPointNode deputy : directlyCalledEpsForEps.keySet()) {
			Set<EntryPointNode> targets = directlyCalledEpsForEps.get(deputy);
			if(targets != null && !targets.isEmpty()) {
				AlNode deputyGraphNode = methodToNode.get(deputy);
				if(deputyGraphNode == null) {
					deputyGraphNode = new AlNode(nextId());
					methodToNode.put(deputy, deputyGraphNode);
				}
				for(EntryPointNode target : targets) {
					Pair<EntryPointNode,EntryPointNode> edge = new Pair<>(deputy,target);
					AlEdge graphEdge = pairToEdge.get(edge);
					if(graphEdge == null) {
						AlNode targetGraphNode = methodToNode.get(target);
						if(targetGraphNode == null) {
							targetGraphNode = new AlNode(nextId());
							methodToNode.put(target, targetGraphNode);
						}
						graphEdge = new AlEdge(nextId(), deputyGraphNode, targetGraphNode);
						pairToEdge.put(edge, graphEdge);
					} else {
						graphEdge.incWeight();
					}
				}
			}
		}
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

package org.sag.arf;

import java.nio.file.Path;
import java.util.Collection;
import org.sag.common.graphtools.AlEdge;
import org.sag.common.graphtools.AlNode;
import org.sag.common.graphtools.Formatter;

public class MultiPathCGFormatter extends Formatter {
	
	protected final MultiPathCGTransformer trans;
	protected final Collection<AlNode> nodes;
	protected final Collection<AlEdge> edges;
	
	public MultiPathCGFormatter(MultiPathCGTransformer trans, Path outputPath) {
		super(trans.applyDefaultColorMap(),trans.applyDefaultShapeMap(),-1,-1,outputPath);
		this.trans = trans;
		this.nodes = trans.getNodes();
		this.edges = trans.getEdges();
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
	public void format() {
		
		
	}

}

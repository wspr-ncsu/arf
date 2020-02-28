package org.sag.arf;

import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.sag.acminer.phases.entrypoints.EntryPoint;
import org.sag.soot.xstream.SootClassContainer;
import org.sag.soot.xstream.SootMethodContainer;
import org.sag.xstream.XStreamInOut;
import org.sag.xstream.XStreamInOut.XStreamInOutInterface;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

@XStreamAlias("EntryPointNode")
public final class EntryPointNode implements XStreamInOutInterface, Comparable<EntryPointNode> {

	@XStreamAlias("EntryPoint")
	private volatile SootMethodContainer entryPoint;
	@XStreamAlias("Stub")
	private volatile SootClassContainer stub;
	@XStreamOmitField
	private volatile String cache;
	
	//for reading in from xml only
	private EntryPointNode() {}
	
	public EntryPointNode(SootMethodContainer entryPoint, SootClassContainer stub) {
		if(entryPoint == null || stub == null)
			throw new IllegalArgumentException();
		this.entryPoint = entryPoint;
		this.stub = stub;
	}
	
	@Override
	public boolean equals(Object o) {
		if(this == o)
			return true;
		if(o == null || !(o instanceof EntryPointNode))
			return false;
		EntryPointNode other = (EntryPointNode)o;
		return Objects.equals(entryPoint, other.entryPoint) && Objects.equals(stub, other.stub);
	}
	
	@Override
	public int hashCode() {
		int i = 17;
		i = i * 31 + Objects.hashCode(entryPoint);
		i = i * 31 + Objects.hashCode(stub);
		return i;
	}
	
	@Override
	public String toString() {
		if(cache == null)
			cache = "{" + Objects.toString(stub) + " : " + Objects.toString(entryPoint) + "}";
		return cache;
	}
	
	@Override
	public int compareTo(EntryPointNode o) {
		int ret = this.stub.compareTo(o.stub);
		if(ret == 0)
			ret = this.entryPoint.compareTo(o.entryPoint);
		return ret;
	}
	
	public SootMethodContainer getEntryPoint() {
		return entryPoint;
	}
	
	public SootClassContainer getStub() {
		return stub;
	}
	
	public EntryPoint getSootEntryPoint() {
		return new EntryPoint(entryPoint.toSootMethod(),stub.toSootClass());
	}
	
	@Override
	public void writeXML(String filePath, Path path) throws Exception {
		XStreamInOut.writeXML(this, filePath, path);
	}
	
	public EntryPointNode readXML(String filePath, Path path) throws Exception {
		return XStreamInOut.readXML(this,filePath, path);
	}
	
	public static EntryPointNode readXMLStatic(String filePath, Path path) throws Exception {
		return new EntryPointNode().readXML(filePath, path);
	}
	
	@XStreamOmitField
	private static AbstractXStreamSetup xstreamSetup = null;

	public static AbstractXStreamSetup getXStreamSetupStatic(){
		if(xstreamSetup == null)
			xstreamSetup = new XStreamSetup();
		return xstreamSetup;
	}
	
	@Override
	public AbstractXStreamSetup getXStreamSetup() {
		return getXStreamSetupStatic();
	}
	
	public static class XStreamSetup extends AbstractXStreamSetup {
		
		@Override
		public void getOutputGraph(LinkedHashSet<AbstractXStreamSetup> in) {
			if(!in.contains(this)) {
				in.add(this);
				SootMethodContainer.getXStreamSetupStatic().getOutputGraph(in);
				SootClassContainer.getXStreamSetupStatic().getOutputGraph(in);
			}
		}

		@Override
		public Set<Class<?>> getAnnotatedClasses() {
			return Collections.singleton(EntryPointNode.class);
		}
		
		@Override
		public void setXStreamOptions(XStream xstream) {
			defaultOptionsNoRef(xstream);
		}
		
	}
	
}

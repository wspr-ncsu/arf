package org.sag.arf;

import java.io.ObjectStreamException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.sag.acminer.database.acminer.Doublet;
import org.sag.common.tools.SortingMethods;
import org.sag.soot.SootSort;
import org.sag.xstream.xstreamconverters.NamedCollectionConverterWithSize;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

@XStreamAlias("Group")
public class GroupContainer implements Comparable<GroupContainer> {
	
	@XStreamAlias("Name")
	private String name;
	
	@XStreamAlias("AvgRatio")
	private double avgRatio;
	
	@XStreamAlias("MissingChecks")
	@XStreamConverter(value=NamedCollectionConverterWithSize.class,strings={"Doublet"},types={Doublet.class})
	private LinkedHashSet<Doublet> missingChecks;
	
	@XStreamAlias("Results")
	@XStreamConverter(value=NamedCollectionConverterWithSize.class,strings={"Result"},types={ResultContainer.class})
	private LinkedHashSet<ResultContainer> results;
	
	@XStreamOmitField
	private Map<EntryPointNode,Set<Doublet>> calleeToDoublets;
	
	@XStreamOmitField
	private boolean hasBeenFinalized;
	
	public GroupContainer(Set<Doublet> missingChecks) {
		this.hasBeenFinalized = false;
		this.missingChecks = missingChecks == null ? null : new LinkedHashSet<>(missingChecks);
		this.calleeToDoublets = null;
		this.results = new LinkedHashSet<>();
		this.avgRatio = 0;
	}
	
	public GroupContainer(String name, Set<Doublet> missingChecks) {
		this(missingChecks);
		this.name = name;
	}
	
	//ReadResolve is always run when reading from XML even if a constructor is run first
	protected Object readResolve() throws ObjectStreamException {
		finalizeData();
		return this;
	}
	
	protected Object writeReplace() throws ObjectStreamException {
		finalizeData();
		return this;
	}
	
	public int hashCode() {
		int i = 17;
		i = i * 31 + Objects.hashCode(name);
		i = i * 31 + Objects.hashCode(missingChecks);
		i = i * 31 + Objects.hashCode(results);
		i = i * 31 + (int)avgRatio;
		return i;
	}
	
	public boolean equals(Object o) {
		if(this == o)
			return true;
		if(o == null || !(o instanceof GroupContainer))
			return false;
		GroupContainer g = (GroupContainer)o;
		return Objects.equals(name, g.name) && avgRatio == g.avgRatio 
				&& Objects.equals(missingChecks, g.missingChecks) && Objects.equals(results, g.results);
	}
	
	@Override
	public String toString() {
		return toString("");
	}
	
	public String toString(String spacer) {
		StringBuilder sb = new StringBuilder();
		sb.append(spacer).append("Group: ").append(name).append("\n");
		sb.append(spacer).append("  AvgRatio: ").append(avgRatio).append("\n");
		sb.append(spacer).append("  MissingChecks: ").append(missingChecks == null ? 0 : missingChecks.size()).append("\n");
		if(missingChecks != null) {
			for(Doublet d : missingChecks) {
				sb.append(spacer).append("    ").append(d).append("\n");
			}
		}
		sb.append(spacer).append("  Sources: ").append((missingChecks != null && calleeToDoublets != null) ? missingChecks.size() : 0).append("\n");
		if(missingChecks != null && calleeToDoublets != null) {
			for(Doublet d : missingChecks) {
				Map<EntryPointNode,Set<String>> calleeToSources = getSourceMethodsPerCallee(d);
				sb.append(spacer).append("    Check: ").append(d).append("\n");
				for(EntryPointNode callee : calleeToSources.keySet()) {
					sb.append(spacer).append("      Callee: ").append(callee).append("\n");
					for(String s : calleeToSources.get(callee)) {
						sb.append(spacer).append("        Source: ").append(s).append("\n");
					}
				}
			}
		}
		sb.append(spacer).append("  Results: ").append(results == null ? 0 : results.size()).append("\n");
		if(results != null) {
			Map<EntryPointNode,Set<ResultContainer>> callerToResult = new HashMap<>();
			for(ResultContainer r : results) {
				Set<ResultContainer> temp = callerToResult.get(r.getCallerEp());
				if(temp == null) {
					temp = new HashSet<>();
					callerToResult.put(r.getCallerEp(), temp);
				}
				temp.add(r);
			}
			for(EntryPointNode caller : callerToResult.keySet()) {
				callerToResult.put(caller, SortingMethods.sortSet(callerToResult.get(caller)));
			}
			callerToResult = SortingMethods.sortMapKeyAscending(callerToResult);
			for(EntryPointNode caller : callerToResult.keySet()) {
				Set<ResultContainer> results = callerToResult.get(caller);
				if(results.size() == 1) {
					ResultContainer r = results.iterator().next();
					sb.append(spacer).append("    ").append("(Ratio: ").append(r.getRatio()).append(") ")
						.append(r.getCallerEp()).append(" ---> ").append(r.getTargetEp()).append("\n");
				} else {
					sb.append(spacer).append("    ").append(caller).append(" ---> \n");
					for(ResultContainer r : results) {
						sb.append(spacer).append("      ").append("(Ratio: ").append(r.getRatio()).append(") ")
							.append(r.getTargetEp()).append("\n");
					}
				}
			}
		}
		return sb.toString();
	}
	
	@Override
	public int compareTo(GroupContainer o) {
		int ret = Double.compare(o.avgRatio, avgRatio);
		if(ret == 0) {
			if(o.missingChecks == null && missingChecks == null)
				ret = 0;
			else if(o.missingChecks == null)
				ret =  -1;
			else if(missingChecks == null)
				ret = 1;
			else
				ret = o.missingChecks.toString().compareToIgnoreCase(missingChecks.toString());
			if(ret == 0)
				ret = Integer.compare(o.results == null ? 0 : o.results.size(), results == null ? 0 : results.size());
		}
		return ret;
	}
	
	public void finalizeData() {
		if(!hasBeenFinalized) {
			if(missingChecks != null && missingChecks.isEmpty())
				missingChecks = null;
			if(results != null && results.isEmpty())
				results = null;
			if(missingChecks != null) {
				missingChecks = SortingMethods.sortSet(missingChecks);
			}
			if(results != null) {
				results = SortingMethods.sortSet(results);
				double total = 0;
				for(ResultContainer r : results) {
					total += r.getRatio();
				}
				avgRatio = total / (double)results.size();
			}
			if(missingChecks != null && results != null) {
				this.calleeToDoublets = new LinkedHashMap<>();
				for(ResultContainer r : results) {
					EntryPointNode	 callee = r.getTargetEp();
					Set<Doublet> missingChecks = r.getMissingChecks();
					if(!this.calleeToDoublets.containsKey(callee)) {
						this.calleeToDoublets.put(callee, missingChecks);
					}
				}
			}
			
			hasBeenFinalized = true;
		}
	}
	
	private void checkFinalize() {
		if(!hasBeenFinalized)
			throw new RuntimeException("Error: " + name + " has not been finalized.");
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public String getName() {
		return name;
	}
	
	public double getAvgRatio() {
		checkFinalize();
		return avgRatio;
	}
	
	public Set<Doublet> getMissingChecks() {
		checkFinalize();
		if(missingChecks == null)
			return Collections.emptySet();
		return new LinkedHashSet<>(missingChecks);
	}
	
	public Set<ResultContainer> getResults() {
		checkFinalize();
		if(results == null)
			return Collections.emptySet();
		return new LinkedHashSet<>(results);
	}
	
	public void addResult(ResultContainer r) {
		if(hasBeenFinalized)
			throw new RuntimeException("Error: " + name + " has already been finalized.");
		results.add(r);
	}
	
	public Map<EntryPointNode,Set<String>> getSourceMethodsPerCallee(Doublet d) {
		checkFinalize();
		if(calleeToDoublets != null) {
			Map<EntryPointNode,Set<String>> ret = new HashMap<>();
			for(EntryPointNode callee : calleeToDoublets.keySet()) {
				Set<String> sources = null;
				for(Doublet dd : calleeToDoublets.get(callee)) {
					if(dd.equals(d)) {
						sources = dd.getSourceMethods();
						break;
					}
				}
				if(sources != null) {
					ret.put(callee, SortingMethods.sortSet(sources,SootSort.smStringComp));
				} else {
					throw new RuntimeException("Error: Could not find match for '" + d + "' for '" + callee + "'");
				}
			}
			return SortingMethods.sortMapKeyAscending(ret);
		}
		return Collections.emptyMap();
	}

}

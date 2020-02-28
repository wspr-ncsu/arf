package org.sag.arf;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.sag.acminer.database.acminer.Doublet;
import org.sag.common.tools.SortingMethods;
import org.sag.xstream.xstreamconverters.NamedCollectionConverterWithSize;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;

@XStreamAlias("Result")
public class ResultContainer implements Comparable<ResultContainer> {
	
	//The target
	@XStreamAlias("TargetEntryPoint")
	private EntryPointNode target;
	
	//The Caller
	@XStreamAlias("CallerEntryPoint")
	private EntryPointNode caller;
	
	//0 = no missing authorization checks
	//The closer ratio is to 1 the more checks are missing
	@XStreamAlias("Ratio")
	private double ratio;
	
	@XStreamAlias("Path")
	@XStreamConverter(value=NamedCollectionConverterWithSize.class,strings={"EntryPointNode"},types={EntryPointNode.class})
	private ArrayList<EntryPointNode> path;
	
	@XStreamAlias("MissingChecks")
	@XStreamConverter(value=NamedCollectionConverterWithSize.class,strings={"Doublet"},types={Doublet.class})
	private LinkedHashSet<Doublet> missingChecks;
	
	//The entry point does not call any other entry points
	public ResultContainer(EntryPointNode caller) {
		this(caller,null,null,0,null);
	}
	
	public ResultContainer(EntryPointNode caller, EntryPointNode target, Set<Doublet> missingChecks, double ratio, 
			List<EntryPointNode> path) {
		Objects.requireNonNull(caller);
		this.caller = caller;
		this.target = target;
		this.missingChecks = missingChecks == null || missingChecks.isEmpty() ? null : SortingMethods.sortSet(missingChecks);
		this.ratio = ratio;
		this.path = path == null || path.isEmpty() ? null : new ArrayList<>(path);
	}
	
	public boolean isEmptyResult() {
		return target == null;
	}
	
	public double getRatio() {
		return ratio;
	}
	
	public EntryPointNode getCallerEp() {
		return caller;
	}
	
	public EntryPointNode getTargetEp() {
		return target;
	}
	
	public Set<Doublet> getMissingChecks() {
		if(missingChecks == null)
			return Collections.emptySet();
		return new LinkedHashSet<>(missingChecks);
	}
	
	public List<EntryPointNode> getPath() {
		if(path == null)
			return Collections.emptyList();
		return new ArrayList<>(path);
	}
	
	@Override
	public int hashCode() {
		int i = 17;
		i = i * 31 + Objects.hashCode(target);
		i = i * 31 + Objects.hashCode(caller);
		i = i * 31 + Objects.hashCode(missingChecks);
		i = i * 31 + (int)ratio;
		return i;
	}
	
	@Override
	public boolean equals(Object o) {
		if(this == o)
			return true;
		if(o == null || !(o instanceof ResultContainer))
			return false;
		ResultContainer r = (ResultContainer)o;
		return ratio == r.ratio && Objects.equals(target, r.target) && Objects.equals(caller, r.caller) 
				&& Objects.equals(missingChecks, r.missingChecks);
	}
	
	@Override
	public String toString() {
		return toString("");
	}
	
	public String toString(String spacer) {
		StringBuilder sb = new StringBuilder();
		if(isEmptyResult()) {
			sb.append(spacer).append("EmptyResult - EP: ").append(Objects.toString(caller)).append("\n");
		} else {
			sb.append(spacer).append("Result - Ratio: ").append(ratio).append("\n");
			sb.append(spacer).append("  CallerEP: ").append(Objects.toString(caller)).append("\n");
			sb.append(spacer).append("  TargetEP: ").append(Objects.toString(target)).append("\n");
			
			if(path != null) {
				sb.append(spacer).append("  Path:\n");
				for(EntryPointNode s : path) {
					sb.append(spacer).append("    ").append(s).append("\n");
				}
			}
			
			sb.append(spacer).append("  MissingChecks: ").append(missingChecks == null ? 0 : missingChecks.size()).append("\n");
			if(missingChecks != null) {
				for(Doublet d : missingChecks) {
					sb.append(spacer).append("    ").append(d).append("\n");
					for(String s : d.getSourceMethods()) {
						sb.append(spacer).append("      ").append(s).append("\n");
					}
				}
			}
		}
		return sb.toString();
	}
	
	@Override
	public int compareTo(ResultContainer o) {
		return comp.compare(this, o);
	}
	
	public static class SortByRatioMissingCheckSizeCallerTarget implements Comparator<ResultContainer> {
		//Smaller ratio/size is easier to look at because the more missing checks the more possibility for noise
		//so sort smaller ratio/size first
		@Override
		public int compare(ResultContainer o1, ResultContainer o2) {
			int ret = 0;
			if(o1.isEmptyResult() && o2.isEmptyResult()) {
				ret = 0;
			} else if(o1.isEmptyResult()) {
				ret = 1;
			} else if(o2.isEmptyResult()) {
				ret = -1;
			}
			if(ret == 0) {
				if(o1.getRatio() == 0.0 && o2.getRatio() == 0.0) {
					ret = 0;
				} else if(o1.getRatio() == 0.0) {
					ret = 1;
				} else if(o2.getRatio() == 0.0) {
					ret = -1;
				}
				if(ret == 0) {
					ret = Double.compare(o1.ratio, o2.ratio);
					if(ret == 0) {
						ret = Integer.compare(o1.missingChecks == null ? 0 : o1.missingChecks.size(), 
								o2.missingChecks == null ? 0 : o2.missingChecks.size());
						if(ret == 0) {
							ret = o1.caller.compareTo(o2.caller);
							if(ret == 0)
								ret = o1.target.compareTo(o2.target);
						}
					}
				}
			}
			return ret;
		}
	}
	
	public static class SortByCallerTargetDoubletRatio implements Comparator<ResultContainer> {
		private final SortByDoubletRatio comp = new SortByDoubletRatio();
		@Override
		public int compare(ResultContainer o1, ResultContainer o2) {
			int ret = 0;
			if(o1.isEmptyResult() && o2.isEmptyResult()) {
				ret = 0;
			} else if(o1.isEmptyResult()) {
				ret = 1;
			} else if(o2.isEmptyResult()) {
				ret = -1;
			}
			if(ret == 0) {
				if(o1.getRatio() == 0.0 && o2.getRatio() == 0.0) {
					ret = 0;
				} else if(o1.getRatio() == 0.0) {
					ret = 1;
				} else if(o2.getRatio() == 0.0) {
					ret = -1;
				}
				if(ret == 0) {
					ret = o1.getCallerEp().compareTo(o2.getCallerEp());
					if(ret == 0) {
						EntryPointNode target1 = o1.getTargetEp();
						EntryPointNode target2 = o2.getTargetEp();
						if(target1 == null && target2 == null) {
							ret = 0;
						} else if(target1 == null) {
							ret = 1;
						} else if(target2 == null) {
							ret = -1;
						} else {
							ret = target1.compareTo(target2);
						}
						if(ret == 0)
							ret = comp.compare(o1, o2);
					}
				}
			}
			return ret;
		}
	}
	
	public static class SortByDoubletRatio implements Comparator<ResultContainer> {
		@Override
		public int compare(ResultContainer o1, ResultContainer o2) {
			Set<Doublet> m1 = SortingMethods.sortSet(o1.getMissingChecks());
			Set<Doublet> m2 = SortingMethods.sortSet(o2.getMissingChecks());
			int ret = 0;
			Iterator<Doublet> it1 = m1.iterator();
			Iterator<Doublet> it2 = m2.iterator();
			if(m1.size() <= m2.size()) {
				while(it1.hasNext() && ret == 0) {
					Doublet d1 = it1.next();
					Doublet d2 = it2.next();
					ret = d1.compareTo(d2);
				}
			} else {
				while(it2.hasNext() && ret == 0) {
					Doublet d1 = it1.next();
					Doublet d2 = it2.next();
					ret = d1.compareTo(d2);
				}
			}
			//Smaller ratio/size is easier to look at because the more missing checks the more possibility for noise
			//so sort smaller ratio/size first
			if(ret == 0) {
				ret = Integer.compare(m1.size(), m2.size());
				if(ret == 0)
					ret = Double.compare(o1.getRatio(), o2.getRatio()); 
			}
			return ret;
		}
	}
	
	private static Comparator<ResultContainer> comp = new SortByCallerTargetDoubletRatio();
	
	public static void setComp(Comparator<ResultContainer> compIn) {
		comp = compIn;
	}
	
	public static Comparator<ResultContainer> getComp() {
		return comp;
	}

}

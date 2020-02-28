package org.sag.arf;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.forge.roaster.Roaster;
import org.jboss.forge.roaster.model.JavaType;
import org.jboss.forge.roaster.model.JavaUnit;
import org.jboss.forge.roaster.model.source.JavaClassSource;
import org.jboss.forge.roaster.model.source.MethodSource;
import org.jboss.forge.roaster.model.source.ParameterSource;
import org.sag.common.io.FileHelpers;
import org.sag.common.io.PrintStreamUnixEOL;
import org.sag.common.tools.SortingMethods;
import com.google.common.collect.ImmutableList;

public class DumpMethodArgNames {
	
	private static final Pattern pat = Pattern.compile("^<(.+): (.+) (.+)\\((.*)\\)>$");
	
	//private static final String  fmt = "%24s: %s%n";
	 
	/*// for the morbidly curious
	<E extends RuntimeException> void genericThrow() throws E {}
	 
	public static void printClassConstructors(Class c) {
		Constructor[] allConstructors = c.getConstructors();
		out.format(fmt, "Number of constructors", allConstructors.length);
		for (Constructor currentConstructor : allConstructors) {
			printConstructor(currentConstructor);
		}  
		Constructor[] allDeclConst = c.getDeclaredConstructors();
		out.format(fmt, "Number of declared constructors",
			allDeclConst.length);
		for (Constructor currentDeclConst : allDeclConst) {
			printConstructor(currentDeclConst);
		}		  
	}*/
	 
	/*public static void printClassMethods(Class c) {
		Method[] allMethods = c.getDeclaredMethods();
		out.format(fmt, "Number of methods", allMethods.length);
		for (Method m : allMethods) {
			printMethod(m);
		}		
	}
	 
	public static void printConstructor(Constructor c) {
		out.format("%s%n", c.toGenericString());
		Parameter[] params = c.getParameters();
		out.format(fmt, "Number of parameters", params.length);
		for (int i = 0; i < params.length; i++) {
			printParameter(params[i]);
		}
	}*/
	 
	/*public static void printMethod(Method m) {
		out.format("%s%n", m.toGenericString());
		out.format(fmt, "Return type", m.getReturnType());
		out.format(fmt, "Generic return type", m.getGenericReturnType());
				 
		if(m.getParameterCount() > 0 && !m.getName().startsWith("lambda")) {
			out.println(m.getName());
			Parameter[] params = m.getParameters();
			for (int i = 0; i < params.length; i++) {
				printParameter(params[i]);
			}
		}
	}
	 
	public static void printParameter(Parameter p) {
		out.format(fmt, "Parameter class", p.getType());
		out.format(fmt, "Parameter name", p.getName());
		out.format(fmt, "Modifiers", p.getModifiers());
		out.format(fmt, "Is implicit?", p.isImplicit());
		out.format(fmt, "Is name present?", p.isNamePresent());
		out.format(fmt, "Is synthetic?", p.isSynthetic());
	}*/
	
	public static List<MethodContainer> getMethods(String name) throws ClassNotFoundException {
		return getMethods(Class.forName(name, false, DumpMethodArgNames.class.getClassLoader()));
	}
	
	public static List<MethodContainer> getMethods(Class<?> c) {
		List<MethodContainer> ret = new ArrayList<>();
		Method[] allMethods = c.getDeclaredMethods();
		for(Method m : allMethods) {
			String name = m.getName();
			Class<?> retType = m.getReturnType();
			String cName = m.getDeclaringClass().getName();
			List<Class<?>> paramTypes = new ArrayList<>();
			List<String> paramNames = new ArrayList<>();
			if(!m.getName().startsWith("lambda")) {
				for(Parameter p : m.getParameters()) {
					paramTypes.add(p.getType());
					paramNames.add(p.getName());
				}
			} else {
				Class<?>[] pTypes = m.getParameterTypes();
				for(int i = 0; i < pTypes.length; i++) {
					paramTypes.add(pTypes[i]);
					paramNames.add("arg" + i);
				}
			}
			ret.add(new MethodContainer(m, name, retType, cName, paramTypes, paramNames));
		}
		Collections.sort(ret);
		return ret;
	}
	
	public static List<JBossMethodContainer> getMethods(String fullClassName, Path srcPath) throws IOException {
		String[] pathParts = fullClassName.split("\\.");
		String className = pathParts[pathParts.length-1];
		String[] innerClasses = null;
		if(className.contains("$")) {
			innerClasses = className.split("\\$");
			className = innerClasses[0];
			innerClasses = Arrays.copyOfRange(innerClasses, 1, innerClasses.length);
		}
		pathParts[pathParts.length-1] = className + ".java";
		Path srcFile = FileHelpers.getPath(srcPath, pathParts);
		String packageName = "";
		if(pathParts.length > 2)
			packageName = String.join(".", Arrays.copyOfRange(pathParts, 0, pathParts.length-1));
		
		if(FileHelpers.checkRWFileExists(srcFile)) {
			try (InputStream in = Files.newInputStream(srcFile)) {
				JavaUnit unit = Roaster.parseUnit(in);
				for(JavaType<?> t : unit.getTopLevelTypes()) {
					if(t.getName().equals(className))
						return getMethods((JavaClassSource)t, innerClasses, className, packageName);
				}
			}
			throw new RuntimeException("Error: Could not find class '" + className + "' in '" + srcFile + "'");
		} else {
			List<Path> fileEntries = new ArrayList<>();
			try (DirectoryStream<Path> stream = Files.newDirectoryStream(srcFile.getParent(), "*.{java}")) {
				for(Path entry : stream) {
					fileEntries.add(entry);
				}
			}
			for(Path fileEntry : fileEntries) {
				try (InputStream in = Files.newInputStream(fileEntry)) {
					JavaUnit unit = Roaster.parseUnit(in);
					for(JavaType<?> t : unit.getTopLevelTypes()) {
						if(t.getName().equals(className))
							return getMethods((JavaClassSource)t, innerClasses, className, packageName);
					}
				}
			}
			throw new RuntimeException("Error: Unable to find .java file containing class '" + className + "' in '" + srcFile.getParent() + "'");
		}
	}
	
	private static List<JBossMethodContainer> getMethods(JavaClassSource clazz, String[] innerClasses, String className, String packageName) {
		List<JBossMethodContainer> ret = new ArrayList<>();
		if(innerClasses != null) {
			for(String innerName : innerClasses) {
				JavaClassSource innerClass = (JavaClassSource)clazz.getNestedType(innerName);
				if(innerClass == null)
					throw new RuntimeException("Error: Unable to find inner class '" + innerName + "' in class '" 
							+ clazz.getQualifiedName() + "'.");
				clazz = innerClass;
			}
		}
		List<MethodSource<JavaClassSource>> methods = clazz.getMethods();
		if(methods != null) {
			for(MethodSource<JavaClassSource> method : methods) {
				List<ParameterSource<JavaClassSource>> params = method.getParameters();
				List<String> paramNames = new ArrayList<>();
				List<String> paramTypes = new ArrayList<>();
				if(params != null && !params.isEmpty()) {
					for(ParameterSource<JavaClassSource> param : params) {
						paramNames.add(param.getName());
						paramTypes.add(getStringForJBossType(param.getType(), param.isVarArgs()));
					}
				}
				String retType = "void";
				if(method.getReturnType() != null)
					retType = getStringForJBossType(method.getReturnType(), false);
				String name = method.getName();
				String fullClassName = clazz.getQualifiedName();
				ret.add(new JBossMethodContainer(name, packageName, className, fullClassName, innerClasses, paramTypes, paramNames, retType));
			}
		}
		return ret;
	}
	
	private static String getStringForJBossType(org.jboss.forge.roaster.model.Type<JavaClassSource> type, boolean isVarArgs) {
		String ret = type.getSimpleName();
		if(!(type.isPrimitive() || ret == "void")) {
			//This is a hack that may cause issues if there are actual classes called T
			//and not just generics
			if(ret.equals("T") || ret.equals("A"))
				ret = "java.lang.Object";
			else
				ret = type.getQualifiedName();
		}
		
		if(type.isArray()) {
			for(int i = 0; i < type.getArrayDimensions(); i++) {
				ret = ret + "[]";
			}
		}
		if(isVarArgs)
			ret += "[]";
		return ret;
	}
	
	public static class JBossMethodContainer implements Comparable<JBossMethodContainer> {
		private final String name;
		private final String packageName;
		private final String className;
		private final String fullClassName;
		private final List<String> innerClasses;
		private final List<String> paramTypes;
		private final List<String> paramNames;
		private final String retType;
		
		public JBossMethodContainer(String name, String packageName, String className, String fullClassName, String[] innerClasses, 
				List<String> paramTypes, List<String> paramNames, String retType) {
			this.name = name;
			this.packageName = packageName;
			this.className = className;
			this.fullClassName = fullClassName;
			if(innerClasses == null)
				this.innerClasses = ImmutableList.of();
			else
				this.innerClasses = ImmutableList.copyOf(innerClasses);
			this.paramTypes = ImmutableList.copyOf(paramTypes);
			this.paramNames = ImmutableList.copyOf(paramNames);
			this.retType = retType;
		}
		
		@Override
		public int hashCode() {
			int i = 17;
			i = i * 31 + Objects.hashCode(name);
			i = i * 31 + Objects.hashCode(packageName);
			i = i * 31 + Objects.hashCode(className);
			i = i * 31 + Objects.hashCode(fullClassName);
			i = i * 31 + Objects.hashCode(innerClasses);
			i = i * 31 + Objects.hashCode(paramTypes);
			i = i * 31 + Objects.hashCode(paramNames);
			i = i * 31 + Objects.hashCode(retType);
			return i;
		}
		
		@Override
		public boolean equals(Object o) {
			if(this == o)
				return true;
			if(o == null || !(o instanceof JBossMethodContainer))
				return false;
			JBossMethodContainer m = (JBossMethodContainer)o;
			return Objects.equals(name, m.name) && Objects.equals(packageName, m.packageName) && Objects.equals(className, m.className)
					&& Objects.equals(fullClassName, m.fullClassName) && Objects.equals(innerClasses, m.innerClasses)
					&& Objects.equals(paramTypes, m.paramTypes) && Objects.equals(paramNames, m.paramNames) && Objects.equals(retType, m.retType);
		}
		
		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("<").append(fullClassName).append(": ").append(retType).append(" ").append(name).append("(");
			boolean first = true;
			for(int i = 0; i < paramTypes.size(); i++) {
				if(first) {
					first = false;
				} else {
					sb.append(", ");
				}
				sb.append(paramTypes.get(i)).append(" ").append(paramNames.get(i));
			}
			sb.append(")>");
			return sb.toString();
		}
		
		public String getSootSignature() {
			soot.options.Options.v().set_allow_phantom_refs(true);
			soot.options.Options.v().set_allow_phantom_elms(true);
			soot.Type retType = soot.Scene.v().getTypeUnsafe(this.retType);
			List<soot.Type> paramTypes = new ArrayList<>();
			for(String t : this.paramTypes) {
				paramTypes.add(soot.Scene.v().getTypeUnsafe(t));
			}
			soot.SootClass sc = soot.Scene.v().getSootClassUnsafe(this.fullClassName);
			return soot.SootMethod.getSignature(sc, name, paramTypes, retType);
		}
		
		public String getSootSignatureWithoutFullQuilifiedNameTypes() {
			soot.options.Options.v().set_allow_phantom_refs(true);
			soot.options.Options.v().set_allow_phantom_elms(true);
			soot.Type retType = soot.Scene.v().getTypeUnsafe(getSimpleName(this.retType));
			List<soot.Type> paramTypes = new ArrayList<>();
			for(String t : this.paramTypes) {
				paramTypes.add(soot.Scene.v().getTypeUnsafe(getSimpleName(t)));
			}
			soot.SootClass sc = soot.Scene.v().getSootClassUnsafe(this.fullClassName);
			return soot.SootMethod.getSignature(sc, name, paramTypes, retType);
		}
		
		@Override
		public int compareTo(JBossMethodContainer o) {
			int ret = SortingMethods.sComp.compare(fullClassName, o.fullClassName);
			if(ret == 0) {
				ret = SortingMethods.sComp.compare(name, o.name);
				if(ret == 0) {
					ret = SortingMethods.sComp.compare(retType, o.retType);
					if(ret == 0)
						ret = SortingMethods.sComp.compare(paramTypes.toString(), o.paramTypes.toString());
				}
			}
			return ret;
		}
	}
	
	public static class MethodContainer implements Comparable<MethodContainer> {
		
		public final Method method;
		public final String name;
		public final Class<?> retType;
		public final String className;
		public final List<Class<?>> paramTypes;
		public final List<String> paramNames;
		
		public MethodContainer(Method method, String name, Class<?> retType, String className, List<Class<?>> paramTypes, List<String> paramNames) {
			this.method = method;
			this.name = name;
			this.retType = retType;
			this.className = className;
			this.paramTypes = ImmutableList.copyOf(paramTypes);
			this.paramNames = ImmutableList.copyOf(paramNames);
		}
		
		@Override
		public boolean equals(Object o) {
			if(this == o)
				return true;
			if(o == null || !(o instanceof MethodContainer))
				return false;
			MethodContainer m = (MethodContainer)o;
			return method.equals(m.method);
		}
		
		@Override
		public int hashCode() {
			return method.hashCode();
		}
		
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("<").append(className).append(": ").append(getStringForType(retType)).append(" ").append(name).append("(");
			boolean first = true;
			for(int i = 0; i < paramTypes.size(); i++) {
				if(first) {
					first = false;
				} else {
					sb.append(", ");
				}
				sb.append(getStringForType(paramTypes.get(i))).append(" ").append(paramNames.get(i));
			}
			sb.append(")>");
			return sb.toString();
		}
		
		private String getStringForType(Class<?> t) {
			return t.getTypeName();
		}
		
		private List<String> getStringsForParamaterTypes() {
			List<String> ret = new ArrayList<>();
			for(Class<?> t : paramTypes) {
				ret.add(getStringForType(t));
			}
			return ret;
		}
		
		public String getSootSignature() {
			soot.options.Options.v().set_allow_phantom_refs(true);
			soot.options.Options.v().set_allow_phantom_elms(true);
			soot.Type retType = soot.Scene.v().getTypeUnsafe(getStringForType(this.retType));
			List<soot.Type> paramTypes = new ArrayList<>();
			for(Class<?> t : this.paramTypes) {
				paramTypes.add(soot.Scene.v().getTypeUnsafe(getStringForType(t)));
			}
			soot.SootClass sc = soot.Scene.v().getSootClassUnsafe(this.className);
			return soot.SootMethod.getSignature(sc, name, paramTypes, retType);
		}

		@Override
		public int compareTo(MethodContainer o) {
			int ret = SortingMethods.sComp.compare(className, o.className);
			if(ret == 0) {
				ret = SortingMethods.sComp.compare(name, o.name);
				if(ret == 0) {
					ret = SortingMethods.sComp.compare(getStringForType(retType), getStringForType(o.retType));
					if(ret == 0)
						ret = SortingMethods.sComp.compare(getStringsForParamaterTypes().toString(), o.getStringsForParamaterTypes().toString());
				}
			}
			return ret;
		}
	}
	
	private static final Map<String,List<String>> parseInputFile(Path in) throws Exception {
		Map<String,List<String>> classesToMethods = new HashMap<>();
		try(BufferedReader br = Files.newBufferedReader(in)) {
			String line;
			while((line = br.readLine()) != null) {
				line = line.trim();
				if(!line.isEmpty() && !line.startsWith("\\") && !line.startsWith("#")) {
					Matcher m = pat.matcher(line);
					if(m.matches()) {
						String o1Class = m.group(1);
						List<String> methods = classesToMethods.get(o1Class);
						if(methods == null) {
							methods = new ArrayList<>();
							classesToMethods.put(o1Class, methods);
						}
						methods.add(line);
					} else {
						throw new RuntimeException("Error: Line '" + line + "' is not a signature.");
					}
				}
			}
		}
		return classesToMethods;
	}
	
	private static String getSimpleName(String name) {
		int index = name.lastIndexOf('.');
		if (index > 0)
			name = name.substring(index + 1);
		index = name.lastIndexOf('$');
		if(index > 0)
			name = name.substring(index + 1);
		return name;
	}
	 
	public static void main(String... args) {
		try {
			if(args[0].equals("-s")) {
				//use straight up java to load the classes
				Path outDir = FileHelpers.getPath(args[1]);
				Path in = FileHelpers.getPath(args[2]);
				Map<String,List<String>> classesToMethods = parseInputFile(in);
				List<String> sigsWithParams = new ArrayList<>();
				for(String className : classesToMethods.keySet()) {
					List<MethodContainer> methods = getMethods(className);
					for(String signature : classesToMethods.get(className)) {
						boolean found = false;
						for(MethodContainer m : methods) {
							if(m.getSootSignature().equals(signature)) {
								sigsWithParams.add(m.toString());
								found = true;
								break;
							}
						}
						if(!found)
							throw new RuntimeException("Error: Could not find '" + signature + "'");
					}
				}
				try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(FileHelpers.getPath(outDir,"methodsWithArgumentNames.txt")))) {
					for(String s : sigsWithParams)
						ps.println(s);
				}
			} else if(args[0].equals("-sa")) {
				Path binPath = FileHelpers.getPath(args[1]);
				Path outDir = FileHelpers.getPath(args[2]);
				List<Path> entries = FileHelpers.getAllDirectoryEntries(binPath);
				for(Path p : entries) {
					if(Files.isRegularFile(p)) {
						String className = binPath.relativize(p).toString().replace(File.separatorChar, '.');
						className = className.substring(0, className.length()-6);
						if(!(className.startsWith("java.") || className.startsWith("sun.") || className.startsWith("javax.")
								|| className.startsWith("jdk.") || className.startsWith("junit."))) {
							List<MethodContainer> methods = getMethods(className);
							try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(
									FileHelpers.getPath(outDir,"allMethodsWithArgumentNames.txt"),StandardOpenOption.CREATE, StandardOpenOption.WRITE, 
									StandardOpenOption.APPEND))) {
								for(MethodContainer m : methods) {
									ps.println(m.toString());
								}
							}
							try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(
									FileHelpers.getPath(outDir,"allMethodsSootSignatures.txt"),StandardOpenOption.CREATE, StandardOpenOption.WRITE, 
									StandardOpenOption.APPEND))) {
								for(MethodContainer m : methods) {
									ps.println(m.getSootSignature());
								}
							}
							try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(
									FileHelpers.getPath(outDir,"allMethodsSootSignaturesWithArgumentNames.txt"),StandardOpenOption.CREATE, StandardOpenOption.WRITE, 
									StandardOpenOption.APPEND))) {
								for(MethodContainer m : methods) {
									ps.println(m.getSootSignature() + "\t" + m.paramNames.toString());
								}
							}
						}
					}
				}
			} else if(args[0].equals("-j")) {
				Path srcPath = FileHelpers.getPath(args[1]);
				Path outDir = FileHelpers.getPath(args[2]);
				Path in = FileHelpers.getPath(args[3]);
				Map<String,List<String>> classesToMethods = parseInputFile(in);
				List<JBossMethodContainer> toOutput = new ArrayList<>();
				for(String className : classesToMethods.keySet()) {
					List<JBossMethodContainer> methods = getMethods(className, srcPath);
					for(String signature : classesToMethods.get(className)) {
						boolean found = false;
						for(JBossMethodContainer m : methods) {
							if(m.getSootSignature().equals(signature)) {
								toOutput.add(m);
								found = true;
								break;
							}
						}
						if(!found) {
							//Because when resolving types to a full name Roaster fails to properly resolve some return and method arguments
							JBossMethodContainer selected = null;
							String fullClassName = null;
							String fullRetType = null;
							String fullArgsTypes = null;
							Matcher m = pat.matcher(signature);
							if(m.matches()) {
								fullClassName = m.group(1).trim();
								fullRetType = m.group(2).trim();
								String retType = getSimpleName(fullRetType);
								String name = m.group(3).trim();
								fullArgsTypes = m.group(4).trim();
								String argsTypes = fullArgsTypes;
								if(!argsTypes.isEmpty()) {
									String[] splits = argsTypes.split(",");
									for(int i = 0; i < splits.length; i++) {
										splits[i] = getSimpleName(splits[i]);
									}
									argsTypes = String.join(",", splits);
								}
								String temp = "<" + fullClassName + ": " + retType + " " + name + "(" + argsTypes + ")>";
								for(JBossMethodContainer method : methods) {
									if(method.getSootSignatureWithoutFullQuilifiedNameTypes().equals(temp)) {
										if(selected == null)
											selected = method;
										else
											throw new RuntimeException("Error: Found mutiple matches for '" + signature + " 1) '" 
													+ selected.getSootSignature() + "' 2) '" + method.getSootSignature() + "'");
									}
								}
								if(selected == null && fullRetType.equals("java.lang.'annotation'.Annotation")) {
									temp = "<" + fullClassName + ": Object " + name + "(" + argsTypes + ")>";
									for(JBossMethodContainer method : methods) {
										if(method.getSootSignatureWithoutFullQuilifiedNameTypes().equals(temp)) {
											if(selected == null)
												selected = method;
											else
												throw new RuntimeException("Error: Found mutiple matches for '" + signature + " 1) '" 
														+ selected.getSootSignature() + "' 2) '" + method.getSootSignature() + "'");
										}
									}
								}
							}
							if(selected == null)
								throw new RuntimeException("Error: Could not find '" + signature + "'");
							
							fullArgsTypes = fullArgsTypes.trim();
							List<String> paramTypes = null;
							if(fullArgsTypes.isEmpty())
								paramTypes = ImmutableList.of();
							else
								paramTypes = Arrays.asList(fullArgsTypes.split(","));
							toOutput.add(new JBossMethodContainer(selected.name, selected.packageName, selected.className, selected.fullClassName, 
									selected.innerClasses.toArray(new String[0]), paramTypes, selected.paramNames, 
									fullRetType));
						}
					}
				}
				Collections.sort(toOutput);
				String inName = com.google.common.io.Files.getNameWithoutExtension(in.getFileName().toString());
				try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(FileHelpers.getPath(outDir,inName + "_with_names.txt")))) {
					for(JBossMethodContainer method : toOutput)
						ps.println(method.toString());
				}
				try(PrintStreamUnixEOL ps = new PrintStreamUnixEOL(Files.newOutputStream(FileHelpers.getPath(outDir,inName + "_without_names.txt")))) {
					for(JBossMethodContainer method : toOutput)
						ps.println(method.getSootSignature());
				}
			}
		} catch(Throwable t) {
			t.printStackTrace();
		}
	}

}

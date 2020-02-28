package org.sag.arf;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OnlyCallerRestrictions {
	
	//From android 8.0.1
	/*public static final int ROOT_UID = 0;
	public static final int SYSTEM_UID = 1000;
	public static final int PHONE_UID = 1001;
	public static final int SHELL_UID = 2000;
	public static final int LOG_UID = 1007;
	public static final int WIFI_UID = 1010;
	public static final int MEDIA_UID = 1013;
	public static final int DRM_UID = 1019;
	public static final int VPN_UID = 1016;
	public static final int KEYSTORE_UID = 1017;
	public static final int NFC_UID = 1027;
	public static final int BLUETOOTH_UID = 1002;
	public static final int MEDIA_RW_GID = 1023;
	public static final int PACKAGE_INFO_GID = 1032;
	public static final int SHARED_RELRO_UID = 1037;
	public static final int AUDIOSERVER_UID = 1041;
	public static final int CAMERASERVER_UID = 1047;
	public static final int WEBVIEW_ZYGOTE_UID = 1051;
	public static final int OTA_UPDATE_UID = 1061;*/
	
	public static final String ROOT_UID_RESTRICTION = "root";
	public static final String SYSTEM_UID_RESTRICTION = "system";
	public static final String PHONE_UID_RESTRICTION = "phone";
	public static final String SHELL_UID_RESTRICTION = "shell";
	public static final String SAME_PACKAGE_RESTRICTION = "calling_uid_matches_package_name";
	
	private Map<String,Set<String>> epToRestrictions;
	
	private OnlyCallerRestrictions() {
		epToRestrictions = new LinkedHashMap<>();
	}
	
	public boolean hasOnlyCallerRestriction(String epSig) {
		return epToRestrictions.containsKey(epSig);
	}
	
	public static OnlyCallerRestrictions parser(Path p) throws Exception {
		OnlyCallerRestrictions ret = new OnlyCallerRestrictions();
		Pattern linePattern = Pattern.compile("^(<[^>]+>)\\s+(.+)$");
		try(BufferedReader br = Files.newBufferedReader(p)) {
			String line;
			while((line = br.readLine()) != null) {
				line = line.trim();
				if(line.isEmpty() || line.startsWith("//"))
					continue;
				Matcher lineMatcher = linePattern.matcher(line);
				if(lineMatcher.matches()) {
					String epSig = lineMatcher.group(1);
					String restStr = lineMatcher.group(2);
					String[] elems = restStr.split("\\|");
					Set<String> res = new LinkedHashSet<>();
					for(String s : elems) {
						s = s.trim().toLowerCase();
						if(s.equals(SYSTEM_UID_RESTRICTION)) {
							res.add(SYSTEM_UID_RESTRICTION);
						} else if(s.equals(ROOT_UID_RESTRICTION)) {
							res.add(ROOT_UID_RESTRICTION);
						} else if(s.equals(PHONE_UID_RESTRICTION)) {
							res.add(PHONE_UID_RESTRICTION);
						} else if(s.equals(SHELL_UID_RESTRICTION)) {
							res.add(SHELL_UID_RESTRICTION);
						} else if(s.equals(SAME_PACKAGE_RESTRICTION)) {
							res.add(SAME_PACKAGE_RESTRICTION);
						} else {
							throw new Exception("Error: Unhandled restriction descriptor '" + s + "'");
						}
					}
					if(!res.isEmpty())
						ret.epToRestrictions.put(epSig, res);
				} else {
					throw new Exception("Error: Unhandled line pattern '" + line + "'");
				}
			}
		}
		return ret;
	}

}

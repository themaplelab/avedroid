package averroes.android;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import averroes.android.resources.ARSCFileParser;
import averroes.android.resources.ARSCFileParser.AbstractResource;
import averroes.android.resources.ARSCFileParser.StringResource;
import averroes.infoflow.android.data.AndroidMethod;
import averroes.infoflow.data.SootMethodAndClass;
import averroes.android.resources.LayoutControl;
import averroes.android.resources.LayoutFileParser;
import averroes.options.AverroesOptions;
import averroes.soot.SootSceneUtil;
import soot.ClassProvider;
import soot.DexClassProvider;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.SourceLocator;
import soot.jimple.infoflow.android.SetupApplication;
import soot.options.Options;

/**
 * Sets up Averroes such that it works with Android applications. Specifically,
 * this class analyzes the apk for xml callbacks and handles the dummy main
 * creation.
 * 
 * @author Michael Appel
 *
 */

public class SetupAndroid {

	private ProcessManifest processMan;
	private final String apkFileLocation;
	
	public SootMethod createDummyMain() {			
		Set<String> entrypoints = processMan.getEntryPointClasses();

		AndroidEntryPointCreator entryPointCreator = new AndroidEntryPointCreator(
				new ArrayList<String>(entrypoints));
		SootMethod dummyMain = entryPointCreator.createDummyMain();
		// If we don't set the super class of the dummy main class, there
		// will be an error
		dummyMain.getDeclaringClass().setSuperclass(G.v().soot_Scene().getSootClass("java.lang.Object"));
		
		return dummyMain;	
	}

	public SetupAndroid() {
		apkFileLocation = AverroesOptions.getApplicationInputs().get(0);
		try {
			//ApkHandler apkHandler = new ApkHandler(apkFileLocation);
			processMan = new ProcessManifest(apkFileLocation);
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
		Options.v().set_soot_classpath(apkFileLocation);
	}
	
	public void findXmlCallbacks() {
		ARSCFileParser resParser = new ARSCFileParser();
		try {
			resParser.parse(apkFileLocation);
			String appPackageName = processMan.getPackageName();
			LayoutFileParser lfp = new LayoutFileParser(appPackageName, resParser);
			calculateCallbackMethodsFast(resParser, lfp);
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
	}
	
	private void calculateCallbackMethodsFast(ARSCFileParser resParser,
			LayoutFileParser lfp) throws IOException {

		Options.v().set_allow_phantom_refs(true);
		lfp.parseLayoutFileDirect(apkFileLocation);
		
		// Collect the XML-based callback methods
		//collectXmlBasedCallbackMethods(resParser, lfp, jimpleClass);
	}

}

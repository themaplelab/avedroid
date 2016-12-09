package averroes.android;

import java.io.File;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jf.dexlib2.dexbacked.raw.ClassDefItem;
import org.jf.dexlib2.dexbacked.raw.MethodIdItem;
import org.jf.dexlib2.dexbacked.raw.RawDexFile;

import averroes.android.infoflow.data.AndroidMethod;
import averroes.android.infoflow.data.SootMethodAndClass;
import averroes.android.resources.ARSCFileParser;
import averroes.android.resources.ARSCFileParser.AbstractResource;
import averroes.android.resources.ARSCFileParser.StringResource;
import averroes.android.resources.LayoutControl;
import averroes.android.resources.LayoutFileParser;
import averroes.exceptions.AverroesException;
import averroes.infoflow.util.SootMethodRepresentationParser;
import averroes.options.AverroesOptions;
import averroes.soot.Names;
import averroes.soot.SootSceneUtil;
import averroes.util.DexUtils;
import soot.ClassProvider;
import soot.DexClassProvider;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.SourceLocator;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.coffi.Util;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.SetupApplication;
import soot.options.Options;

/**
 * Sets up Averroes such that it works with Android applications. Specifically,
 * this class analyzes the apk for xml callbacks and handles the dummy main
 * creation. Many parts of the code originate from FlowDroid.
 * 
 * @author Michael Appel
 *
 */

public class SetupAndroid {

	private static SetupAndroid instance;
	
	private final int apiVersion;

	private ProcessManifest processMan;
	private String apkFileLocation;
	private SootMethod dummyMain = null;
	private Set<String> entrypoints = null;
	
	private RawDexFile rawDex;
	
	private final Map<String, Set<SootMethodAndClass>> xmlCallbacks =
			new HashMap<String, Set<SootMethodAndClass>>(10000);
	private final Map<String, Set<Integer>> layoutClasses =
			new HashMap<String, Set<Integer>>();

	
	public static SetupAndroid v() {
		if (instance == null) {
			try {
				instance = new SetupAndroid();
			}
			catch (AverroesException ex) {
				ex.printStackTrace();
			}
		}
		return instance;
	}
	
	private SetupAndroid() throws AverroesException {
		apkFileLocation = AverroesOptions.getApk();
		try {
			processMan = new ProcessManifest(apkFileLocation);
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
		// TODO: Scene.v().getAndroidAPIVersion() works only with a "platforms" directory.
		// I'm not sure if the first parameter has to be the platforms directory or
		// if the platforms directory has to be set by an extra call.
		// In any case, the call returns -1 without a platforms directory.
		// We work with the targetSdkVersion, as given in the manifest file for now.
		//apiVersion = Scene.v().getAndroidAPIVersion(AverroesOptions.getAndroidJar(), apkFileLocation);
		apiVersion = processMan.targetSdkVersion();
		if (apiVersion == -1){
			throw new AverroesException("Couldn't find the Android API version in the manifest file.",
					new Throwable());
		}
		this.entrypoints = processMan.getEntryPointClasses();

		Options.v().set_soot_classpath(apkFileLocation + File.pathSeparator + AverroesOptions.getAndroidJar());
	}
	
	public SootMethod getDummyMainMethod() {			
		if (dummyMain != null) {
			return dummyMain;
		}
		
		Options.v().set_soot_classpath(apkFileLocation + File.pathSeparator + AverroesOptions.getAndroidJar());
		System.out.println(Options.v().soot_classpath());
		
		AndroidEntryPointCreator entryPointCreator = createEntryPointCreator();
		dummyMain = entryPointCreator.createDummyMain();
		dummyMain.getDeclaringClass().setSuperclass(G.v().soot_Scene().getSootClass(Names.JAVA_LANG_OBJECT));
		
		return dummyMain;	
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

		// TODO: Check for correctness
		// Class loading: In order to find XML callbacks we process the
		// jimple code of components (activities?) because we need the mapping between layout files
		// and components (this is achieved by examining the parameter of the setContentView() call).
		// Thus, the necessary classes need to be added to the scene.
		// The question is whether the following code is correct and whether
		// the Scene needs to be reset afterwards

		Options.v().set_process_dir(Collections.singletonList(apkFileLocation));
		//Options.v().set_allow_phantom_refs(true);
		Scene.v().loadNecessaryClasses();
					
		findClassLayoutMappings();
		
		Options.v().set_allow_phantom_refs(true);
		lfp.parseLayoutFileDirect(apkFileLocation);
		
		// Collect the XML-based callback methods
		collectXmlBasedCallbackMethods(resParser, lfp);
	}
	
	private void collectXmlBasedCallbackMethods(ARSCFileParser resParser,
			LayoutFileParser lfp) {
		// Collect the XML-based callback methods
		for (Entry<String, Set<Integer>> lcentry : layoutClasses.entrySet()) {
			final SootClass callbackClass = Scene.v().getSootClass(lcentry.getKey());

			for (Integer classId : lcentry.getValue()) {
				AbstractResource resource = resParser.findResource(classId);
				if (resource instanceof StringResource) {
					final String layoutFileName = ((StringResource) resource).getValue();

					// Add the callback methods for the given class
					Set<String> callbackMethods = lfp.getCallbackMethods().get(layoutFileName);
					if (callbackMethods != null) {
						for (String methodName : callbackMethods) {
							final String subSig = "void " + methodName + "(android.view.View)";

							// The callback may be declared directly in the
							// class
							// or in one of the superclasses
							SootClass currentClass = callbackClass;
							while (true) {
								SootMethod callbackMethod = currentClass.getMethodUnsafe(subSig);
								if (callbackMethod != null) {
									addCallbackMethod(callbackClass.getName(), new AndroidMethod(callbackMethod));
									break;
								}
								if (!currentClass.hasSuperclass()) {
									System.err.println("Callback method " + methodName + " not found in class "
											+ callbackClass.getName());
									break;
								}
								currentClass = currentClass.getSuperclass();
							}
						}
					}

					// For user-defined views, we need to emulate their
					// callbacks
					Set<LayoutControl> controls = lfp.getUserControls().get(layoutFileName);
					if (controls != null)
						for (LayoutControl lc : controls)
							registerCallbackMethodsForView(callbackClass, lc);
				} else
					System.err.println("Unexpected resource type for layout class");
			}
		}
	}

	/**
	 * Registers the callback methods in the given layout control so that they
	 * are included in the dummy main method
	 * @param callbackClass The class with which to associate the layout
	 * callbacks
	 * @param lc The layout control whose callbacks are to be associated with
	 * the given class
	 */
	private void registerCallbackMethodsForView(SootClass callbackClass, LayoutControl lc) {
		// Ignore system classes
		if (callbackClass.getName().startsWith("android."))
			return;
		if (lc.getViewClass().getName().startsWith("android."))
			return;
		
		// Check whether the current class is actually a view
		{
			SootClass sc = lc.getViewClass();
			boolean isView = false;
			while (sc.hasSuperclass()) {
				if (sc.getName().equals("android.view.View")) {
					isView = true;
					break;
				}
				sc = sc.getSuperclass();
			}
			if (!isView)
				return;
		}

		// There are also some classes that implement interesting callback
		// methods.
		// We model this as follows: Whenever the user overwrites a method in an
		// Android OS class, we treat it as a potential callback.
		SootClass sc = lc.getViewClass();
		Set<String> systemMethods = new HashSet<String>(10000);
		for (SootClass parentClass : Scene.v().getActiveHierarchy().getSuperclassesOf(sc)) {
			if (parentClass.getName().startsWith("android."))
				for (SootMethod sm : parentClass.getMethods())
					if (!sm.isConstructor())
						systemMethods.add(sm.getSubSignature());
		}

		// Scan for methods that overwrite parent class methods
		for (SootMethod sm : sc.getMethods())
			if (!sm.isConstructor())
				if (systemMethods.contains(sm.getSubSignature()))
					// This is a real callback method
					addCallbackMethod(callbackClass.getName(), new AndroidMethod(sm));
	}
	
	private void addCallbackMethod(String layoutClass, AndroidMethod callbackMethod) {
		Set<SootMethodAndClass> methods = this.xmlCallbacks.get(layoutClass);
		if (methods == null) {
			methods = new HashSet<SootMethodAndClass>();
			this.xmlCallbacks.put(layoutClass, methods);
		}
		methods.add(new AndroidMethod(callbackMethod));
	}
	
	private AndroidEntryPointCreator createEntryPointCreator() {
		AndroidEntryPointCreator entryPointCreator = new AndroidEntryPointCreator(new ArrayList<String>(
				this.entrypoints));
		Map<String, List<String>> callbackMethodSigs = new HashMap<String, List<String>>();
		for (String className : this.xmlCallbacks.keySet()) {
			List<String> methodSigs = new ArrayList<String>();
			callbackMethodSigs.put(className, methodSigs);
			for (SootMethodAndClass am : this.xmlCallbacks.get(className))
				methodSigs.add(am.getSignature());
		}
		entryPointCreator.setCallbackFunctions(callbackMethodSigs);
		return entryPointCreator;
	}

	private void findClassLayoutMappings() {
		for (SootClass sc : Scene.v().getApplicationClasses()) {
			if (sc.isConcrete()) {
				for (SootMethod sm : sc.getMethods()) {
					if (!sm.isConcrete())
						continue;
					
					for (Unit u : sm.retrieveActiveBody().getUnits()) {
						if (u instanceof Stmt) {
							Stmt stmt = (Stmt) u;
							if (stmt.containsInvokeExpr()) {
								InvokeExpr inv = stmt.getInvokeExpr();
								if (invokesSetContentView(inv)) {
									for (Value val : inv.getArgs())
										if (val instanceof IntConstant) {
											IntConstant constVal = (IntConstant) val;
											Set<Integer> layoutIDs = this.layoutClasses.get(sm.getDeclaringClass().getName());
											if (layoutIDs == null) {
												layoutIDs = new HashSet<Integer>();
												this.layoutClasses.put(sm.getDeclaringClass().getName(), layoutIDs);
											}
											layoutIDs.add(constVal.value);
										}
								}
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Checks whether this invocation calls Android's Activity.setContentView
	 * method
	 * @param inv The invocaton to check
	 * @return True if this invocation calls setContentView, otherwise false
	 */
	protected boolean invokesSetContentView(InvokeExpr inv) {
		String methodName = SootMethodRepresentationParser.v().getMethodNameFromSubSignature(
				inv.getMethodRef().getSubSignature().getString());
		if (!methodName.equals("setContentView"))
			return false;
		
		// In some cases, the bytecode points the invocation to the current
		// class even though it does not implement setContentView, instead
		// of using the superclass signature
		SootClass curClass = inv.getMethod().getDeclaringClass();
		while (curClass != null) {
			if (curClass.getName().equals("android.app.Activity")
					|| curClass.getName().equals("android.support.v7.app.ActionBarActivity"))
				return true;
			if (curClass.declaresMethod("void setContentView(int)"))
				return false;
			curClass = curClass.hasSuperclass() ? curClass.getSuperclass() : null;
		}
		return false;
	}
	
	public RawDexFile getRawDex() {
		// needs to be done after the constructor, hence the field is initialized here
		if (rawDex == null) {
			try {
				rawDex = DexUtils.getRawDex(new File(apkFileLocation), null);
			}
			catch (IOException ioEx) {
				ioEx.printStackTrace();
			}
		}
		return rawDex;
	}
	
	public int getReferencedApplicationClassCount() {
		// TODO: Refactor
		String[] classes = ClassDefItem.getClasses(getRawDex());
		List<String> result = new LinkedList<>();
		
		String patternString = AverroesOptions.getEscapedApplicationRegex();
		Pattern p = Pattern.compile(patternString);	

		for (String s: classes) {		
			Type jimpleType = Util.v().jimpleTypeOfFieldDescriptor(s);
			Matcher m = p.matcher(jimpleType.toString());
			while (m.find()) {
				String match = m.group();
				result.add(match);
			}	
		}
		
		/*for (String s: result) {
			System.out.println(s);
		}*/
		return result.size();
	}
	
	public int getReferencedApplicationMethodCount() {
		String[] methods = MethodIdItem.getMethods(getRawDex());
		
		List<String> result = new LinkedList<>();
		
		String patternString = AverroesOptions.getEscapedApplicationRegex();
		Pattern p = Pattern.compile(patternString);	

		for (String s: methods) {		
			String[] clazzAndMethod = s.split("-");
			Type jimpleType = Util.v().jimpleTypeOfFieldDescriptor(clazzAndMethod[0]);
			Matcher m = p.matcher(jimpleType.toString());
			while (m.find()) {
				String match = m.group();
				result.add(s);
			}	
		}
		/*for (String s: result) {
			System.out.println(s);
		}*/
		return result.size();	
	}
		
	public int getApiVersion() {	
		return apiVersion;
	}
	
	public String getApkFileLocation() {
		return apkFileLocation;
	}

}

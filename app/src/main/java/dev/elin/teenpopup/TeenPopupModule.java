package dev.elin.teenpopup;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.List;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class TeenPopupModule extends XposedModule {
    private static final String TAG = "ElinTeenPopup";
    private static final String TARGET = "com.hypergryph.skland";
    private static final String TIPS_DIALOG = "com.hypergryph.skland.teenager.TeenagerTipsDialogV2";
    private static final String TIPS_ACTIVITY =
            "com.hypergryph.skland.teenager.page.tipsactivity.TeenagerTipsActivity";
    private static final long[] RETRY_DELAYS_MS = {600, 1500, 3000, 5000};
    private static final String[] GATE_CLASSES = {
            "com.hypergryph.skland.teenager.TeenagerTipsDialogViewModel",
            "com.hypergryph.skland.teenager.data.TeenagerConfig",
            "com.hypergryph.skland.teenager.data.DialogMarkRequest",
            "com.hypergryph.skland.service.ITeenagerService$Config",
            "com.hypergryph.theme.data.Teenager",
            "com.hypergryph.theme.data.TeenagerMeta",
            "com.hypergryph.skland.service.IAccountService$TeenagerStub",
            "com.hypergryph.skland.service.IAccountService$TeenagerMetaStub"
    };

    private static String nativeStatus = "not loaded";

    static {
        try {
            System.loadLibrary("teenhide");
            nativeStatus = "loaded";
        } catch (Throwable throwable) {
            nativeStatus = String.valueOf(throwable);
        }
    }

    private static native void teen_refresh_maps();

    private static boolean loadingCopy;
    private String processName = "";
    private boolean appInstalled;
    private boolean shellHooked;
    private int blocked;

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        processName = param.getProcessName();
        info("module loaded in " + processName + " native=" + nativeStatus);
    }

    private void hookShellLoad() {
        if (shellHooked) {
            return;
        }
        shellHooked = true;
        try {
            Class<?> runtime = Class.forName("java.lang.Runtime");
            for (Method method : runtime.getDeclaredMethods()) {
                String name = method.getName();
                if (name.equals("nativeLoad")) {
                    hookExecutable(method, this::swapDexHelper);
                }
            }
            info("shell load hooks armed");
        } catch (Throwable throwable) {
            info("shell load hook failed " + throwable);
        }
    }

    private Object swapDexHelper(XposedInterface.Chain chain) throws Throwable {
        if (loadingCopy) {
            return chain.proceed();
        }
        String source = libraryPath(chain.getArgs());
        if (source == null || !source.contains("libDexHelper.so")) {
            return chain.proceed();
        }
        try {
            teen_refresh_maps();
            File copy = patchedDexHelper(source);
            Object[] next = chain.getArgs().toArray();
            for (int i = 0; i < next.length; i++) {
                if (next[i] instanceof String text && text.contains("libDexHelper.so")) {
                    next[i] = copy.getAbsolutePath();
                }
            }
            info("swap " + copy.getAbsolutePath());
            return chain.proceed(next);
        } catch (Throwable throwable) {
            info("swap failed " + throwable);
            return chain.proceed();
        }
    }

    private static String libraryPath(List<Object> args) {
        if (args == null) {
            return null;
        }
        for (int i = args.size() - 1; i >= 0; i--) {
            if (args.get(i) instanceof String text && text.contains("libDexHelper.so")) {
                return text;
            }
        }
        for (int i = args.size() - 1; i >= 0; i--) {
            if (args.get(i) instanceof String text && (text.endsWith(".so") || text.contains("/"))) {
                return text;
            }
        }
        return null;
    }

    private static File patchedDexHelper(String source) throws Exception {
        byte[] data = readFile(source);
        byte[] needle = "/proc/self/maps".getBytes(StandardCharsets.US_ASCII);
        byte[] replacement = "/proc/self/fd/9".getBytes(StandardCharsets.US_ASCII);
        int replaced = 0;
        for (int i = 0; i + needle.length <= data.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                System.arraycopy(replacement, 0, data, i, replacement.length);
                replaced++;
            }
        }
        if (replaced == 0) {
            throw new IllegalStateException("maps string missing");
        }
        File dir = new File("/data/user/0/com.hypergryph.skland/cache");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("cache missing");
        }
        File out = new File(dir, "libDexHelper.so");
        if (out.exists() && !out.setWritable(true, true)) {
            throw new IllegalStateException("cache not writable");
        }
        try (FileOutputStream stream = new FileOutputStream(out)) {
            stream.write(data);
        }
        if (!out.setWritable(false, false)) {
            throw new IllegalStateException("chmod failed");
        }
        return out;
    }

    private static byte[] readFile(String path) throws Exception {
        try (FileInputStream stream = new FileInputStream(path);
             ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[65536];
            int n;
            while ((n = stream.read(chunk)) > 0) {
                buffer.write(chunk, 0, n);
            }
            return buffer.toByteArray();
        }
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!TARGET.equals(param.getPackageName())) {
            return;
        }
        if (processName.contains(":")) {
            debug("skip subprocess " + processName);
            return;
        }
        ClassLoader initial = param.getClassLoader();
        Handler handler = new Handler(Looper.getMainLooper());
        for (long delay : RETRY_DELAYS_MS) {
            handler.postDelayed(() -> installAppHooks(resolveLoader(initial)), delay);
        }
        info("wait for unpacked dex");
    }

    private ClassLoader resolveLoader(ClassLoader fallback) {
        try {
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Method currentApplication = activityThread.getDeclaredMethod("currentApplication");
            Object app = currentApplication.invoke(null);
            if (app instanceof Application application && TARGET.equals(application.getPackageName())) {
                ClassLoader loader = application.getClassLoader();
                if (loader != null) {
                    return loader;
                }
            }
        } catch (Throwable t) {
            debug("application loader unavailable: " + t);
        }
        return fallback;
    }

    private void installAppHooks(ClassLoader loader) {
        if (appInstalled || loader == null) {
            return;
        }
        Class<?> tips = findClass(loader, TIPS_DIALOG);
        Class<?> tipsActivity = findClass(loader, TIPS_ACTIVITY);
        if (tips == null && tipsActivity == null) {
            debug("app dex not ready");
            return;
        }
        int gates = 0;
        if (tips != null) {
            hookTipsType(tips);
        }
        Class<?> sheet = findClass(loader, "com.hypergryph.skland.teenager.TeenagerTipsDialogSheet");
        if (sheet != null) {
            hookTipsType(sheet);
        }
        if (tipsActivity != null) {
            hookTipsActivity(tipsActivity);
        }
        Class<?> bottomSheet = findClass(loader, "com.hypergryph.skland.skui.bottomsheetv2.SKBottomSheetContentDialogFragmentV2");
        if (bottomSheet != null) {
            hookNamed(bottomSheet, "show", this::blockTipsShow);
            hookNamed(bottomSheet, "showNow", this::blockTipsShow);
        }
        Class<?> nav = findClass(loader, "androidx.navigation.NavController");
        if (nav != null) {
            hookNamed(nav, "navigate", this::blockTipsRoute);
        }
        for (String name : GATE_CLASSES) {
            Class<?> type = findClass(loader, name);
            if (type != null) {
                gates += hookPopupGates(type);
            }
        }
        Class<?> viewModel = findClass(loader, "com.hypergryph.skland.teenager.TeenagerTipsDialogViewModel");
        if (viewModel != null) {
            gates += hookPopupGates(viewModel);
        }
        appInstalled = tips != null || tipsActivity != null;
        info("app hooks installed tips=" + (tips != null) + " activity=" + (tipsActivity != null) + " gates=" + gates);
    }

    private void hookTipsActivity(Class<?> type) {
        Class<?> cursor = type;
        while (cursor != null && cursor != Activity.class && !cursor.getName().startsWith("android.")) {
            try {
                Method method = cursor.getDeclaredMethod("onCreate", Bundle.class);
                hookExecutable(method, chain -> {
                    Object self = chain.getThisObject();
                    if (self instanceof Activity activity && isTipsName(activity.getClass().getName())) {
                        noteBlocked("finish " + activity.getClass().getName());
                        activity.finish();
                        activity.overridePendingTransition(0, 0);
                    }
                    return chain.proceed();
                });
                return;
            } catch (NoSuchMethodException ignored) {
                cursor = cursor.getSuperclass();
            }
        }
        debug("no app onCreate on " + type.getName());
    }

    private void hookTipsType(Class<?> type) {
        for (Method method : type.getDeclaredMethods()) {
            if (!canHook(method)) {
                continue;
            }
            String name = method.getName();
            if (name.equals("show") || name.equals("showNow")) {
                hookExecutable(method, this::blockTipsShow);
            }
        }
    }

    private int hookPopupGates(Class<?> type) {
        int count = 0;
        for (Method method : type.getDeclaredMethods()) {
            if (!canHook(method) || method.getParameterCount() != 0) {
                continue;
            }
            Class<?> ret = method.getReturnType();
            if (ret != boolean.class && ret != Boolean.class) {
                continue;
            }
            String name = method.getName();
            if (!name.equals("isPopup") && !name.equals("getPopup")
                    && !name.equals("getTeenagerPopup") && !name.equals("isTeenagerPopup")) {
                continue;
            }
            hookExecutable(method, chain -> {
                noteBlocked(type.getSimpleName() + "." + name + " -> false");
                return skip(chain);
            });
            count++;
        }
        if (count > 0) {
            debug("popup gates on " + type.getName() + " = " + count);
        }
        return count;
    }

    private Object blockTipsShow(XposedInterface.Chain chain) throws Throwable {
        if (shouldBlockCaller(chain.getThisObject())) {
            noteBlocked("skip " + chain.getExecutable().getName() + " " + nameOf(chain.getThisObject()));
            return skip(chain);
        }
        return chain.proceed();
    }

    private Object blockTipsRoute(XposedInterface.Chain chain) throws Throwable {
        for (Object arg : chain.getArgs()) {
            if (arg instanceof String route && isTipsRoute(route)) {
                noteBlocked("drop route " + route);
                return skip(chain);
            }
        }
        return chain.proceed();
    }

    private void hookNamed(Class<?> type, String name, XposedInterface.Hooker hooker) {
        for (Method method : type.getDeclaredMethods()) {
            if (method.getName().equals(name) && canHook(method)) {
                hookExecutable(method, hooker);
            }
        }
    }

    private void hookMethod(Class<?> type, String name, Class<?>[] params, XposedInterface.Hooker hooker) {
        try {
            Method method = type.getDeclaredMethod(name, params);
            hookExecutable(method, hooker);
        } catch (NoSuchMethodException e) {
            debug("missing " + type.getName() + "." + name);
        }
    }

    private void hookExecutable(Method method, XposedInterface.Hooker hooker) {
        try {
            hook(method)
                    .setId(idOf(method))
                    .setExceptionMode(BuildConfig.DEBUG
                            ? XposedInterface.ExceptionMode.PASSTHROUGH
                            : XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(hooker);
            debug("hook " + idOf(method));
        } catch (Throwable t) {
            debug("hook failed " + idOf(method) + " " + t);
        }
    }

    private static boolean canHook(Method method) {
        int mod = method.getModifiers();
        return !Modifier.isAbstract(mod) && !method.isSynthetic();
    }

    private static String idOf(Method method) {
        StringBuilder id = new StringBuilder(method.getDeclaringClass().getName())
                .append('#')
                .append(method.getName());
        for (Class<?> param : method.getParameterTypes()) {
            id.append(',').append(param.getName());
        }
        return id.toString();
    }

    private boolean shouldBlockCaller(Object self) {
        if (self != null && isTipsName(self.getClass().getName())) {
            return true;
        }
        return fromTipsUi();
    }

    private static boolean isTipsName(String name) {
        return name.contains("TeenagerTips");
    }

    private static boolean isTipsRoute(String route) {
        return route.contains("TeenagerTips")
                || route.contains("teenager_tips")
                || route.contains("TeenagerDialog");
    }

    private boolean fromTipsUi() {
        for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
            String name = element.getClassName();
            if (name.startsWith("dev.elin.teenpopup")) {
                continue;
            }
            if (isTipsName(name)) {
                return true;
            }
        }
        return false;
    }

    private static Object skip(XposedInterface.Chain chain) {
        Executable executable = chain.getExecutable();
        if (executable instanceof Method method) {
            Class<?> ret = method.getReturnType();
            if (ret == boolean.class) {
                return Boolean.FALSE;
            }
            if (ret == int.class) {
                return 0;
            }
            if (ret == long.class) {
                return 0L;
            }
        }
        return null;
    }

    private Class<?> findClass(ClassLoader loader, String name) {
        try {
            return Class.forName(name, false, loader);
        } catch (Throwable t) {
            debug("class missing " + name);
            return null;
        }
    }

    private static String nameOf(Object obj) {
        return obj == null ? "null" : obj.getClass().getName();
    }

    private void noteBlocked(String message) {
        blocked++;
        info("blocked #" + blocked + " " + message);
    }

    private void info(String message) {
        log(Log.INFO, TAG, message);
    }

    private void debug(String message) {
        if (BuildConfig.DEBUG) {
            log(Log.DEBUG, TAG, message);
        }
    }
}

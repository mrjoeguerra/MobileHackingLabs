# Strings Lab — Exploitation Report

**Author:** Jose Manuel Guerra Jr.
**Target:** `com.mobilehackinglab.challenge` (Strings Lab)
**Purpose:** Document the static & dynamic analysis, exploitation steps, and final flag retrieval for the Strings CTF challenge. This report is written to showcase the methodology, evidence, and remediation suggestions.

---

# Executive Summary

This assessment demonstrates how a simple Android app (debuggable, with an exported activity and a hard-coded crypto key/IV) can be exploited using static analysis (JADX/Ghidra) and dynamic instrumentation (Frida). By: (1) identifying an exported `Activity2` that validates a SharedPreference value and a Base64-encoded secret, (2) using Frida to set the required SharedPreference and observe decrypt results, and (3) scanning the loaded native library memory, we retrieved the flag:

```
MHL{IN_THE_MEMORY}
```

The vulnerability is intentional for the lab, but the chain of problems (exported entrypoint, hard-coded key/IV, debuggable app, and sensitive data present in native memory) illustrates real-world insecure patterns.

---

# Scope & Objective

* **Scope:** Single APK (`com.mobilehackinglab.challenge`) provided by the lab.
* **Objective:** Find and extract the hidden flag (format `MHL{...}`) from the application.

---

# Environment & Tools

* Host: Windows 10 (attacker) — connected to Android VM/emulator (Genymotion / Android Studio emulator).
* Tools:

  * JADX — static decompilation of APK
  * Ghidra — native library inspection
  * Frida (Frida-server on device, frida CLI on host) — dynamic instrumentation
  * adb — app install / intent invocation
  * Basic binary/memory scanning via Frida script (Memory.scan / hexdump)

---

# Findings (high level)

1. **MainActivity**: Minimal Kotlin wrapper that loads `libchallenge.so` (contains `stringFromJNI`) and writes a date key (`UUU0133`) into SharedPreferences name `DAD4` via method `KLOW()`. Not useful for flag directly.
2. **AndroidManifest**:

   * `Activity2` declared **exported="true"** with intent-filter:

     ```
     <data android:scheme="mhl" android:host="labs"/>
     ```

     This means external apps/URIs can open it.
   * Application `debuggable="true"` (enables easy instrumentation).
3. **Activity2**:

   * Checks that it was started with `Intent.ACTION_VIEW`.
   * Confirms SharedPreferences `DAD4:UUU0133` equals today's date (format `dd/MM/yyyy`).
   * Expects the URI `mhl://labs/<base64>` where `<base64>` decodes to a plaintext secret.
   * Decrypts a hard-coded ciphertext `bqGrDKdQ8zo26HflRsGvVA==` using AES/CBC/PKCS5Padding with:

     * Key bytes from string `"your_secret_key_1234567890123456"` (hard-coded in code).
     * IV is from `Activity2Kt.fixedIV = "1234567890123456"` (hard-coded).
   * If decrypted string equals the decoded URI payload, it `System.loadLibrary("flag")` and calls native `getflag()` to get the flag string.
4. **Native library `libflag.so`**: Heavily obfuscated in reverse tools; however, when loaded into memory the flag string is present in plaintext within its memory region.
5. **Result**: By setting SharedPreferences correctly and calling the activity with the correct base64 payload, the native library loaded and the flag was found in memory.

---

# Exploitation Methodology (step-by-step)

### 1. Static discovery

* Decompile APK with JADX.
* Inspect `MainActivity` → note `KLOW()` writes current date to `DAD4:UUU0133`.
* Inspect `AndroidManifest.xml` → `Activity2` exported with `mhl` scheme and `labs` host.
* Inspect `Activity2` (decompiled Kotlin) → learns:

  * How SharedPreferences is validated.
  * The decrypt routine signature and the hard-coded ciphertext.
  * The hard-coded key string used to create `SecretKeySpec`.
  * That `System.loadLibrary("flag")` and `getflag()` are called only if checks pass.

### 2. Prepare Frida scripts

Two scripts used:

* `open_activity.js` — constructs an `Intent` with `mhl://labs/<base64>` and starts the target activity from app context.
* `find_secrets.js` — hooks `Activity2` methods to:

  * Force-set `DAD4:UUU0133` to today’s value (returned by `cd()`).
  * Log `cd()` and the SharedPreference contents.
  * Hook `decrypt(...)` to log the decrypted plaintext.
  * Hook `getflag()` and `Toast.makeText()` to capture messages.
  * After library loaded, scan `libflag.so` memory for `MHL{` pattern and dump the hexdump.

> Key dynamic observations taken from Frida output:

```
Uri value: mhl://labs/bWhsX3NlY3JldF8xMzM3
Decrypted result: mhl_secret_1337
getflag() returned: Success
Memory scan dumped: MHL{IN_THE_MEMORY}
```

### 3. How the secret was recovered

* Frida showed `decrypt(...)` returned `mhl_secret_1337`. That was the plaintext the app expected to receive as the decoded payload.
* Base64 of `mhl_secret_1337` = `bWhsX3NlY3JldF8xMzM3`.
* Calling `mhl://labs/bWhsX3NlY3JldF8xMzM3` (with the date sharedpref set) caused the app to load `libflag.so` and call `getflag()`.
* A memory scan of `libflag.so` located ASCII `MHL{IN_THE_MEMORY}`.

---

# Reproduction steps (concise)

1. Install the APK on a device/emulator with Frida-server running and device `adb` accessible.
2. Run Frida attaching to package:

   ```
   frida -Uf com.mobilehackinglab.challenge -l find_secrets.js -l open_activity.js
   ```

   (The `-U` or `-f` flags depend on device/usage; the example above forces spawn and loads scripts.)
3. Observe output. The decrypted secret and memory hexdump will appear. The flag recovered:

   ```
   MHL{IN_THE_MEMORY}
   ```

---

# Artifacts

* **Flag:** `MHL{IN_THE_MEMORY}`
* **Important strings & constants:**

  * Ciphertext (base64): `bqGrDKdQ8zo26HflRsGvVA==`
  * Hard-coded AES key string: `"your_secret_key_1234567890123456"`
  * Fixed IV: `"1234567890123456"`
  * Expected plaintext secret: `mhl_secret_1337`
  * Base64 payload to pass in URI: `bWhsX3NlY3JldF8xMzM3`

---

# Final Scripts (for appendix / reproduction)

> **open_activity.js**

```js
Java.perform(function () {
    setTimeout(function () {
        var Intent = Java.use('android.content.Intent');
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        if (context === null) { console.error('Failed to get application context.'); return; }
        var Uri = Java.use('android.net.Uri');
        var uriString = "mhl://labs/bWhsX3NlY3JldF8xMzM3"; // base64(mhl_secret_1337)
        var uri = Uri.parse(uriString);
        var intent = Intent.$new("android.intent.action.VIEW", uri);
        intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
        context.startActivity(intent);
    }, 500);
});
```

> **find_secrets.js**

```js
Java.perform(function() {
    var Intrinsics = Java.use('kotlin.jvm.internal.Intrinsics');
    var Activity2 = Java.use('com.mobilehackinglab.challenge.Activity2');

    Activity2.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
        console.log("onCreate called");

        // Set today's date in SharedPreferences to satisfy check
        var cdValue = this.cd();
        var sharedPreferences = this.getSharedPreferences("DAD4", 0);
        var editor = sharedPreferences.edit();
        editor.putString("UUU0133", cdValue);
        editor.apply();
        console.log("SharedPreference UUU0133:", sharedPreferences.getString("UUU0133", null));
        console.log("Value of cd():", cdValue);

        // Check intent info
        var intent = this.getIntent();
        console.log("Intent action:", intent.getAction.call(intent) === "android.intent.action.VIEW");
        var uri = intent.getData();
        console.log("Uri value:", uri ? uri.toString() : "null");

        // Call decrypt to reveal plaintext (the app calls it too)
        var keyBytes = Java.array('byte', [121,111,117,114,95,115,101,99,114,101,116,95,107,101,121,95,49,50,51,52,53,54,55,56,57,48,49,50,51,52,53,54]);
        var key = Java.use('javax.crypto.spec.SecretKeySpec').$new(keyBytes, "AES");
        var algorithm = "AES/CBC/PKCS5Padding";
        var cipherText = "bqGrDKdQ8zo26HflRsGvVA==";
        try {
            var dec = this.decrypt(algorithm, cipherText, key);
            console.log("Decrypted result:", dec);
        } catch (e) {
            console.error("Decrypt fail:", e);
        }

        // after native lib loads, scan memory for flag pattern
        setTimeout(function () {
            try {
                var library = Process.getModuleByName("libflag.so");
                var pattern = '4d 48 4c 7b'; // "MHL{"
                var results = Memory.scanSync(library.base, library.size, pattern);
                if (results.length > 0) {
                    var flag_addr = results[0].address;
                    console.log(hexdump(flag_addr, {length: 128}));
                } else {
                    console.log("No flag pattern found in libflag.so");
                }
            } catch (e) {
                console.error("Memory scan error:", e);
            }
        }, 1000);

        // Call original onCreate to preserve normal behavior
        this.onCreate(savedInstanceState);
    };

    // Hook decrypt to log runtime decrypts
    Activity2.decrypt.overload('java.lang.String','java.lang.String','javax.crypto.spec.SecretKeySpec').implementation = function(algorithm, cipherText, key) {
        console.log("decrypt called with algorithm:", algorithm, "cipherText:", cipherText);
        var result = this.decrypt(algorithm, cipherText, key);
        console.log("Decrypted:", result);
        return result;
    };

    Activity2.getflag.implementation = function() {
        console.log("getflag() called");
        var r = this.getflag();
        console.log("getflag() returned:", r);
        return r;
    };

    var Toast = Java.use('android.widget.Toast');
    Toast.makeText.overload('android.content.Context','java.lang.CharSequence','int').implementation = function(context, text, duration) {
        console.log("Toast message:", text ? text.toString() : "");
        return this.makeText(context, text, duration);
    };
});
```

---

# Impact & Risk

* **Impact:** Confidential data (the flag) present in process memory could be read by an attacker with instrumentation access. In real applications, presence of secrets or flag-like values in native memory could lead to credential exfiltration.
* **Likelihood:** Moderate if a device is running a debuggable app or has been compromised / attacker can run Frida. Exported activities increase attack surface.
* **Severity:** Medium — in the lab the behavior is intended; in production similar patterns (hard-coded keys, exported endpoints, debuggable builds) can lead to data leak and unauthorized access.

---

# Remediation & Recommendations

To prevent similar weaknesses in production apps:

1. **Avoid embedding secrets in code or libraries.**

   * Don’t hard-code symmetric keys, IVs, or plaintext secrets in Java/Kotlin/NDK.
   * Use Android Keystore for keys or perform sensitive crypto operations on a trusted backend.

2. **Don’t expose entry points unnecessarily.**

   * Set `android:exported="false"` for activities that should not be invoked by external apps.
   * If an activity must be exported, require a custom permission or verify calling package/x509 certificate signature.

3. **Remove debug features in production builds.**

   * Ensure `android:debuggable="false"` in release manifests.
   * Strip debugging symbols from release native libraries.

4. **Avoid storing secrets in plain native memory.**

   * If native code must generate secrets, use techniques to lock memory and zero sensitive buffers when done.
   * Consider server-side validation instead of local static secrets.

5. **Use runtime integrity checks and anti-instrumentation defenses** (balanced and not a silver bullet).

   * Verify app signature at runtime.
   * Detect common instrumentation hooks (Frida) and fail closed for sensitive actions — but be aware these can be bypassed and can interfere with legitimate debugging.

6. **Harden intent handling.**

   * Validate incoming URIs carefully.
   * Prefer deep links that require a signature check or nonce from a back-end server to prevent replay.

---

# Conclusion

The Strings Lab demonstrates a compact chain of weaknesses: debug build, exported activity, hard-coded crypto material, and sensitive data present in native memory. Using Frida and a small set of scripts, we reproduced the expected lab exploitation path and extracted the flag `MHL{IN_THE_MEMORY}`. The work shown underscores common secure-coding pitfalls and remediation controls that production developers should adopt to reduce similar risks.

---

# Appendix (Suggested file name & submission)

* **Report file name:** `StringsLab_ExploitReport_Jose_Guerra.pdf` (or `.docx`)
* **Deliverables to attach:**

  * This report (PDF/Word)
  * `open_activity.js`
  * `find_secrets.js`
  * adb/frida commands used (in a plain text `commands.txt`)

---

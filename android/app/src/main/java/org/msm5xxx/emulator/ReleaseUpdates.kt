package org.msm5xxx.emulator

import android.app.Activity
import android.app.PendingIntent
import android.app.ActivityOptions
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.ensureActive
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

internal data class ReleaseApk(val version: String, val url: String, val size: Long, val sha256: String)

internal object ReleaseUpdates {
    private const val API = "https://api.github.com/repos/ancalina/msm5xxx-emulator/releases/latest"
    private const val MAX_APK = 1024L * 1024 * 1024

    private fun connection(url: String): HttpURLConnection {
        require(URL(url).protocol == "https") { "HTTPS required" }
        return (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000; readTimeout = 30000
            setRequestProperty("User-Agent", "MSM5xxx-Android")
            // Redirects are followed explicitly so an HTTPS response cannot downgrade transport.
            instanceFollowRedirects = false
        }
    }

    private fun open(url: String): HttpURLConnection {
        var address = url
        repeat(6) {
            val request = connection(address)
            val status = request.responseCode
            if (status in listOf(301,302,303,307,308)) {
                val next = request.getHeaderField("Location") ?: error("Missing redirect")
                address = URL(URL(address), next).toString(); request.disconnect()
            } else {
                if (status != 200) { request.disconnect(); error("HTTP $status") }
                return request
            }
        }
        error("Too many redirects")
    }

    suspend fun check(activity: Activity): ReleaseApk? = withContext(Dispatchers.IO) {
        val local = java.io.File(activity.filesDir,"update-release.json").takeIf {
            activity.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0 && it.isFile
        }
        val request = if (local == null) open(API) else null
        val text = try {
            (local?.inputStream() ?: request!!.inputStream).use { input ->
                val bytes = java.io.ByteArrayOutputStream().use { output ->
                    val buffer=ByteArray(8192)
                    while (true) { val count=input.read(buffer); if (count<0) break
                        require(output.size()+count <= 1024*1024) { "Release metadata too large" }; output.write(buffer,0,count) }
                    output.toByteArray()
                }
                require(bytes.size <= 1024 * 1024) { "Release metadata too large" }
                bytes.toString(Charsets.UTF_8)
            }
        } finally { request?.disconnect() }
        val release = JSONObject(text)
        require(!release.optBoolean("draft") && (!release.optBoolean("prerelease") || local != null))
        val version = release.getString("tag_name").removePrefix("v")
        val current = activity.packageManager.getPackageInfo(activity.packageName,0).versionName.orEmpty()
        if (version == current || !ReleaseVersion.newer(version.substringBefore("-"),current)) return@withContext null
        val assets = release.getJSONArray("assets")
        val candidates = (0 until assets.length()).map { assets.getJSONObject(it) }
            .filter { it.getString("name").endsWith(".apk") && it.getString("name").contains("arm64") }
        require(candidates.size == 1) { "Release must contain one arm64 APK" }
        val asset = candidates.single()
        val url = asset.getString("browser_download_url")
        require(url.startsWith("https://github.com/ancalina/msm5xxx-emulator/releases/download/") ||
            (local != null && url == java.io.File(activity.filesDir,"update.apk").toURI().toString()))
        val size = asset.getLong("size"); require(size in 1..MAX_APK)
        val digest = asset.getString("digest").removePrefix("sha256:")
        require(digest.matches(Regex("[a-fA-F0-9]{64}"))) { "Missing SHA-256 digest" }
        ReleaseApk(version,url,size,digest.lowercase())
    }

    suspend fun install(activity: Activity, release: ReleaseApk) = withContext(Dispatchers.IO) {
        val file = java.io.File(activity.cacheDir,"release.apk")
        try {
            val local = java.io.File(activity.filesDir,"update.apk").takeIf {
                activity.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0 && release.url == it.toURI().toString()
            }
            val request = if (local == null) open(release.url) else null
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            try { (local?.inputStream() ?: request!!.inputStream).use { input -> file.outputStream().use { output ->
                val buffer = ByteArray(65536)
                while (true) {
                    coroutineContext.ensureActive()
                    val count = input.read(buffer); if (count < 0) break
                    total += count; require(total <= release.size) { "APK exceeds declared size" }
                    digest.update(buffer,0,count); output.write(buffer,0,count)
                }
            } } } finally { request?.disconnect() }
            require(total == release.size && digest.digest().joinToString("") { "%02x".format(it) } == release.sha256) { "APK checksum mismatch" }
            val pm = activity.packageManager
            val archive = pm.getPackageArchiveInfo(file.path,PackageManager.GET_SIGNING_CERTIFICATES) ?: error("Invalid APK")
            val installed = pm.getPackageInfo(activity.packageName,PackageManager.GET_SIGNING_CERTIFICATES)
            require(archive.packageName == activity.packageName && archive.versionName == release.version && archive.longVersionCode > installed.longVersionCode) { "APK package or version mismatch" }
            // shortcut: accept the current signer; add proof-of-rotation history when rotating the release key.
            require(archive.signingInfo!!.apkContentsSigners.toSet() == installed.signingInfo!!.apkContentsSigners.toSet()) { "APK signing certificate mismatch" }
            coroutineContext.ensureActive()
            val installer = pm.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                setAppPackageName(activity.packageName); setSize(total)
                if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
            }
            val id = installer.createSession(params)
            try {
                installer.openSession(id).use { session ->
                    session.openWrite("base.apk",0,total).use { output ->
                        file.inputStream().use { input ->
                            val buffer=ByteArray(65536)
                            while (true) {
                                coroutineContext.ensureActive()
                                val count=input.read(buffer);if(count<0)break
                                output.write(buffer,0,count)
                            }
                        }; session.fsync(output)
                    }
                    val result = Intent(activity,UpdateInstallActivity::class.java)
                    val options = if (Build.VERSION.SDK_INT >= 35) ActivityOptions.makeBasic().apply {
                        // Android 15 requires explicit creator opt-in for this OS installer callback.
                        setPendingIntentCreatorBackgroundActivityStartMode(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
                    }.toBundle() else null
                    val callback = PendingIntent.getActivity(activity,id,result,
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,options)
                    coroutineContext.ensureActive()
                    session.commit(callback.intentSender)
                }
            } catch (error: Exception) { installer.abandonSession(id); throw error }
        } finally { file.delete() }
    }
}

/** Explicit, non-exported callback launches the OS confirmation screen. */
class UpdateInstallActivity : ComponentActivity() {
    override fun onCreate(state: android.os.Bundle?) {
        super.onCreate(state)
        if (intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE) == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            @Suppress("DEPRECATION") val confirmation = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
            if (confirmation != null) startActivity(confirmation)
        } else if (intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE) != PackageInstaller.STATUS_SUCCESS) {
            android.util.Log.w("ReleaseUpdates", "System installation failed: "+intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE))
            android.widget.Toast.makeText(this,R.string.update_install_failed,android.widget.Toast.LENGTH_LONG).show()
        }
        finish()
    }
}

@Composable
internal fun UpdatesUi(activity: Activity, settings: Boolean) {
    val prefs = remember { activity.getSharedPreferences("launcher",Activity.MODE_PRIVATE) }
    var automatic by remember { mutableStateOf(prefs.getBoolean("check_updates",true)) }
    var release by remember { mutableStateOf<ReleaseApk?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var transfer by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    val scope = rememberCoroutineScope()
    val latest = stringResource(R.string.update_current)
    val failed = stringResource(R.string.update_failed)
    fun check(manual: Boolean) { scope.launch {
        busy = true
        try { release = ReleaseUpdates.check(activity); if (manual && release == null) message = latest }
        catch (error: Exception) { if (error is kotlinx.coroutines.CancellationException) throw error; android.util.Log.w("ReleaseUpdates","Update check failed",error); if (manual) message = failed }
        finally { busy = false }
    } }
    LaunchedEffect(Unit) { if (!settings && automatic) check(false) }
    if (settings) {
        ListItem(headlineContent={Text(stringResource(R.string.updates))})
        ListItem(headlineContent={Text(stringResource(R.string.update_automatic))}, trailingContent={
            Switch(checked=automatic,onCheckedChange={ automatic=it; prefs.edit().putBoolean("check_updates",it).apply() })
        })
        ListItem(headlineContent={Text(stringResource(R.string.update_check))},modifier=Modifier.clickable(enabled=!busy) {check(true)})
    }
    release?.let { available ->
        AlertDialog(onDismissRequest={transfer?.cancel();release=null},title={Text(stringResource(R.string.update_available))},
            text={if (busy) { Column { CircularProgressIndicator(); Text(stringResource(R.string.update_downloading)) } } else Text(stringResource(R.string.update_download_prompt,available.version))},
            confirmButton={TextButton(enabled=!busy,onClick={transfer=scope.launch {
                busy=true
                try {
                    if (!activity.packageManager.canRequestPackageInstalls()) {
                        activity.startActivity(Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,android.net.Uri.parse("package:"+activity.packageName)))
                    } else { ReleaseUpdates.install(activity,available); release=null }
                } catch (error: Exception) {if (error is kotlinx.coroutines.CancellationException) throw error; android.util.Log.w("ReleaseUpdates","Update download failed",error); message=failed; release=null}
                finally {busy=false;transfer=null}
            }}) {Text(stringResource(R.string.update_download))}},
            dismissButton={TextButton(onClick={transfer?.cancel();release=null}) {Text(stringResource(android.R.string.cancel))}})
    }
    message?.let { text -> AlertDialog(onDismissRequest={message=null},title={Text(stringResource(R.string.updates))},text={Text(text)},
        confirmButton={TextButton(onClick={message=null}) {Text(stringResource(android.R.string.ok))}}) }
}

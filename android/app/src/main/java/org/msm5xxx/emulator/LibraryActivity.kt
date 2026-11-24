package org.msm5xxx.emulator

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import java.io.File

class LibraryActivity : ComponentActivity() {
    private lateinit var library: FirmwareLibraryScreen
    private var language = "auto"
    private val filePicker = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        acceptDocument(false, result.resultCode, result.data)
    }
    private val folderPicker = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        acceptDocument(true, result.resultCode, result.data)
    }
    private val settingsPicker = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        when (result.data?.getStringExtra(SettingsActivity.EXTRA_ACTION)) {
            SettingsActivity.ACTION_ADD_FOLDER -> pick(true)
            SettingsActivity.ACTION_IMPORT_FILE -> pick(false)
        }
    }

    override fun attachBaseContext(base: Context) {
        language = base.getSharedPreferences("launcher", MODE_PRIVATE).getString("ui_language", "auto") ?: "auto"
        super.attachBaseContext(localizedContext(base))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val external = getExternalFilesDir(null)
        if (!intent.getBooleanExtra("returning", false) && external != null && File(external, "autorun").isFile) {
            startActivity(Intent(this, MainActivity::class.java))
            finish()
            return
        }
        library = FirmwareLibraryScreen(this, object : FirmwareLibraryScreen.Listener {
            override fun chooseFolder() = pick(true)
            override fun importFile() = pick(false)
            override fun openSettings() {
                settingsPicker.launch(Intent(this@LibraryActivity, SettingsActivity::class.java))
            }
            override fun boot(uri: Uri, name: String, size: Long) {
                library.ensureEntry(uri, name, size)
                library.dismiss()
                startActivity(Intent(this@LibraryActivity, MainActivity::class.java).setData(uri)
                    .putExtra("name", name).putExtra("size", size))
            }
        })
        val previous = getSharedPreferences("launcher", MODE_PRIVATE)
        library.setPreviousCopy(previous.getString("copy", null), previous.getString("name", null))
    }

    override fun onResume() {
        super.onResume()
        if (language != getSharedPreferences("launcher", MODE_PRIVATE).getString("ui_language", "auto")) {
            recreate()
            return
        }
        if (::library.isInitialized) library.show()
    }

    override fun onPause() {
        if (::library.isInitialized) library.dismiss()
        super.onPause()
    }

    override fun onDestroy() {
        if (::library.isInitialized) library.close()
        super.onDestroy()
    }

    private fun pick(folder: Boolean) {
        val picker = Intent(if (folder) Intent.ACTION_OPEN_DOCUMENT_TREE else Intent.ACTION_OPEN_DOCUMENT)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        if (!folder) picker.addCategory(Intent.CATEGORY_OPENABLE).type = "*/*"
        try { if (folder) folderPicker.launch(picker) else filePicker.launch(picker) }
        catch (_: ActivityNotFoundException) { library.showMessage(getString(R.string.error_no_picker)) }
    }

    private fun acceptDocument(folder: Boolean, result: Int, data: Intent?) {
        val uri = data?.data ?: return
        if (result != RESULT_OK || !::library.isInitialized) return
        try {
            if (data.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
                contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_: SecurityException) { }
        if (folder) library.addFolder(uri)
        else library.importFile(uri, null)
    }


}

internal fun localizedContext(base: Context): Context {
    val language = base.getSharedPreferences("launcher", Context.MODE_PRIVATE).getString("ui_language", "auto")
    if (language == "auto") return base
    val config = android.content.res.Configuration(base.resources.configuration)
    config.setLocale(java.util.Locale.forLanguageTag(language ?: "en"))
    return base.createConfigurationContext(config)
}

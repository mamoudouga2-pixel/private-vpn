package com.novavpn.app

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private val Bg = Color(0xFF07110F)
private val Panel = Color(0xFF0E1B18)
private val PanelSoft = Color(0xFF142722)
private val Accent = Color(0xFF63DDB7)
private val Mint = Color(0xFF9AF0D2)
private val Muted = Color(0xFF9CB4AC)
private val Danger = Color(0xFFFF9EAA)
private val Line = Color(0xFF29423A)
private val Warm = Color(0xFFE2C99A)

private data class Country(
    val code: String,
    val name: String,
    val flag: String,
    val region: String,
    val available: Boolean
)

private class NovaTunnel : Tunnel {
    override fun getName(): String = "novavpn"
    override fun onStateChange(newState: Tunnel.State) { }
}

private class TokenVault(context: Context) {
    private val prefs = context.getSharedPreferences("nova_vault", Context.MODE_PRIVATE)
    private val alias = "NovaVPN_Token_AES_GCM"

    private fun secretKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun encrypt(clear: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        return cipher.iv + cipher.doFinal(clear)
    }

    private fun decrypt(encrypted: ByteArray): ByteArray {
        require(encrypted.size > 12) { "Encrypted data is incomplete." }
        val iv = encrypted.copyOfRange(0, 12)
        val payload = encrypted.copyOfRange(12, encrypted.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(payload)
    }

    fun saveToken(token: String) {
        val encrypted = encrypt(token.toByteArray(Charsets.UTF_8))
        prefs.edit().putString("token_secure", Base64.encodeToString(encrypted, Base64.NO_WRAP)).apply()
    }

    fun writeSecureFile(file: File, content: String) {
        file.parentFile?.mkdirs()
        file.writeBytes(encrypt(content.toByteArray(Charsets.UTF_8)))
    }

    fun readSecureFile(file: File): String = String(decrypt(file.readBytes()), Charsets.UTF_8)

    fun readToken(): String? {
        return try {
            val data = prefs.getString("token_secure", null) ?: return null
            String(decrypt(Base64.decode(data, Base64.NO_WRAP)), Charsets.UTF_8)
        } catch (_: Exception) { null }
    }

    fun saveApi(url: String) { prefs.edit().putString("api_url", url).apply() }
    fun readApi(): String = prefs.getString("api_url", "") ?: ""
    fun saveSelectedCountry(code: String) { prefs.edit().putString("selected_country", code).apply() }
    fun readSelectedCountry(): String = prefs.getString("selected_country", "") ?: ""
    fun clearToken() { prefs.edit().remove("token_secure").apply() }
    fun clearSelectedCountry() { prefs.edit().remove("selected_country").apply() }
}

private object NovaApi {
    fun request(baseUrl: String, path: String, method: String, token: String? = null, body: JSONObject? = null): JSONObject {
        val cleanBase = baseUrl.trim().trimEnd('/')
        val parsed = URL(cleanBase)
        require(parsed.protocol.equals("https", ignoreCase = true)) { "Use your control-panel HTTPS address (https://…)." }
        val connection = (URL(cleanBase + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15000
            readTimeout = 20000
            setRequestProperty("Accept", "application/json")
            if (token != null) setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
        }
        try {
            if (body != null) connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val response = stream?.bufferedReader()?.use { it.readText() } ?: "{}"
            val json = try { JSONObject(response) } catch (_: Exception) { JSONObject() }
            if (status !in 200..299) throw IllegalStateException(json.optString("detail", "Request failed ($status)."))
            return json
        } finally {
            connection.disconnect()
        }
    }
}

class MainActivity : ComponentActivity() {
    private lateinit var backend: GoBackend
    private lateinit var vault: TokenVault
    private val tunnel = NovaTunnel()

    private var apiUrl by mutableStateOf("")
    private var username by mutableStateOf("")
    private var loginPassword by mutableStateOf("")
    private var token by mutableStateOf<String?>(null)
    private var displayName by mutableStateOf("")
    private var locations by mutableStateOf<List<Country>>(emptyList())
    private var selectedCode by mutableStateOf("")
    private var connected by mutableStateOf(false)
    private var busy by mutableStateOf(false)
    private var statusText by mutableStateOf("Sign in to your private network.")
    private var errorText by mutableStateOf<String?>(null)
    private var mustChangePassword by mutableStateOf(false)
    private var oldPassword by mutableStateOf("")
    private var newPassword by mutableStateOf("")

    private val vpnPermissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) connectSelectedProfile() else {
            busy = false
            statusText = "Android VPN permission was not granted."
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        backend = GoBackend(applicationContext)
        vault = TokenVault(applicationContext)
        apiUrl = vault.readApi()
        token = vault.readToken()
        selectedCode = vault.readSelectedCountry()
        connected = try { backend.getState(tunnel) == Tunnel.State.UP } catch (_: Exception) { false }

        setContent {
            NovaVpnTheme {
                NovaVpnScreen(
                    loggedIn = token != null,
                    apiUrl = apiUrl, onApiUrl = { apiUrl = it },
                    username = username, onUsername = { username = it },
                    loginPassword = loginPassword, onLoginPassword = { loginPassword = it },
                    displayName = displayName,
                    locations = locations, selectedCode = selectedCode,
                    connected = connected, busy = busy, status = statusText, error = errorText,
                    mustChangePassword = mustChangePassword,
                    oldPassword = oldPassword, onOldPassword = { oldPassword = it },
                    newPassword = newPassword, onNewPassword = { newPassword = it },
                    onLogin = { signIn() },
                    onChangePassword = { updatePassword() },
                    onSelect = { country -> if (!connected && !busy && country.available) { selectedCode = country.code; vault.saveSelectedCountry(country.code); errorText = null } },
                    onConnect = { connectOrPrepare() },
                    onRefresh = { if (!busy) loadLocations() },
                    onLogout = { logout() }
                )
            }
        }

        if (token != null) loadAccount()
        else if (connected) {
            lifecycleScope.launch {
                try { withContext(Dispatchers.IO) { backend.setState(tunnel, Tunnel.State.DOWN, null) } } catch (_: Exception) { }
                connected = false
            }
        }
    }

    private fun signIn() {
        if (busy) return
        busy = true; errorText = null; statusText = "Securely signing in…"
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    NovaApi.request(apiUrl, "/api/v1/auth/login", "POST", body = JSONObject()
                        .put("username", username.trim()).put("password", loginPassword))
                }
                val newToken = result.getString("access_token")
                vault.saveApi(apiUrl.trim().trimEnd('/'))
                vault.saveToken(newToken)
                token = newToken
                displayName = result.optString("username", username.trim())
                loginPassword = ""
                mustChangePassword = result.optBoolean("must_change_password", false)
                if (mustChangePassword) {
                    busy = false
                    statusText = "Set a new password to secure your account."
                } else {
                    loadLocations()
                }
            } catch (e: Exception) {
                busy = false; statusText = "Sign-in failed."; errorText = e.message ?: "Could not sign in."
            }
        }
    }

    private fun loadAccount() {
        busy = true
        lifecycleScope.launch {
            try {
                val me = withContext(Dispatchers.IO) { NovaApi.request(apiUrl, "/api/v1/me", "GET", token) }
                displayName = me.optString("username", "Member")
                mustChangePassword = me.optBoolean("must_change_password", false)
                if (mustChangePassword) { busy = false; statusText = "Change your temporary password to continue." }
                else loadLocations()
            } catch (e: Exception) {
                vault.clearToken(); token = null; locations = emptyList(); busy = false
                errorText = e.message ?: "Please sign in again."
                statusText = "Your session could not be restored."
            }
        }
    }

    private fun loadLocations() {
        val activeToken = token ?: return
        busy = true; statusText = "Loading your private locations…"
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) { NovaApi.request(apiUrl, "/api/v1/locations", "GET", activeToken) }
                val array = result.getJSONArray("locations")
                val list = buildList {
                    for (i in 0 until array.length()) {
                        val item = array.getJSONObject(i)
                        add(Country(item.getString("code"), item.getString("name"), item.optString("flag", "🌐"),
                            item.optString("region", ""), item.optBoolean("available", false)))
                    }
                }
                locations = list
                if (selectedCode.isBlank() || list.none { it.code == selectedCode && it.available }) {
                    selectedCode = list.firstOrNull { it.available }?.code ?: list.firstOrNull()?.code.orEmpty()
                    if (selectedCode.isNotBlank()) vault.saveSelectedCountry(selectedCode)
                }
                busy = false
                statusText = if (list.any { it.available }) "Your private VPN locations are ready." else "No VPN locations have been assigned to this account yet."
                errorText = null
            } catch (e: Exception) {
                busy = false; statusText = "Could not load locations."; errorText = e.message ?: "Server connection failed."
            }
        }
    }

    private fun updatePassword() {
        val activeToken = token ?: return
        if (newPassword.length < 12) { errorText = "Use at least 12 characters for your new password."; return }
        busy = true; errorText = null; statusText = "Updating password…"
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    NovaApi.request(apiUrl, "/api/v1/auth/change-password", "POST", activeToken,
                        JSONObject().put("current_password", oldPassword).put("new_password", newPassword))
                }
                oldPassword = ""; newPassword = ""; mustChangePassword = false
                loadLocations()
            } catch (e: Exception) {
                busy = false; statusText = "Password update failed."; errorText = e.message ?: "Could not update password."
            }
        }
    }

    private fun profileFile(code: String): File = File(File(filesDir, "profiles").apply { mkdirs() }, "$code.profile")

    private fun connectOrPrepare() {
        if (connected) { disconnectTunnel(); return }
        val selected = locations.firstOrNull { it.code == selectedCode }
        if (selected == null || !selected.available) { errorText = "This country has not been assigned to your account."; return }
        val file = profileFile(selected.code)
        val activeToken = token ?: return
        busy = true; errorText = null; statusText = "Securely loading ${selected.name} profile…"
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    NovaApi.request(apiUrl, "/api/v1/profiles/${selected.code}/config", "GET", activeToken)
                }
                val configText = result.getString("config")
                withContext(Dispatchers.IO) {
                    Config.parse(configText.reader())
                    vault.writeSecureFile(file, configText)
                }
                busy = false; statusText = "${selected.name} profile secured on this device. Connecting…"
                requestVpnPermission()
            } catch (e: Exception) {
                busy = false; statusText = "Could not prepare VPN profile."; errorText = e.message ?: "Profile download failed."
            }
        }
    }

    private fun requestVpnPermission() {
        val intent: Intent? = VpnService.prepare(this)
        if (intent != null) vpnPermissionLauncher.launch(intent) else connectSelectedProfile()
    }

    private fun connectSelectedProfile() {
        val selected = locations.firstOrNull { it.code == selectedCode } ?: return
        val file = profileFile(selected.code)
        if (!file.exists()) { busy = false; errorText = "The VPN profile is missing. Sign in and try again."; return }
        busy = true; errorText = null; statusText = "Connecting to ${selected.name}…"
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val configText = vault.readSecureFile(file)
                    val config = Config.parse(configText.reader())
                    backend.setState(tunnel, Tunnel.State.UP, config)
                }
                connected = true; busy = false; statusText = "Protected connection is active · ${selected.name}."
            } catch (e: Exception) {
                connected = false; busy = false; statusText = "Connection could not be established."
                errorText = e.message ?: "Check the server status and assigned profile."
            }
        }
    }

    private fun disconnectTunnel() {
        if (busy) return
        busy = true; statusText = "Disconnecting securely…"
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) { backend.setState(tunnel, Tunnel.State.DOWN, null) }
                connected = false; busy = false; statusText = "VPN disconnected."
            } catch (e: Exception) {
                busy = false; errorText = e.message ?: "Disconnect failed."; statusText = "Check VPN status."
            }
        }
    }

    private fun logout() {
        if (connected) {
            lifecycleScope.launch { try { withContext(Dispatchers.IO) { backend.setState(tunnel, Tunnel.State.DOWN, null) } } catch (_: Exception) { } }
        }
        connected = false
        vault.clearToken(); token = null; locations = emptyList(); selectedCode = ""
        File(filesDir, "profiles").deleteRecursively()
        vault.clearSelectedCountry()
        mustChangePassword = false; oldPassword = ""; newPassword = ""
        statusText = "Signed out. Your local VPN profiles were removed."; errorText = null
    }
}

private enum class MainTab { HOME, LOCATIONS, SETTINGS }

@Composable
private fun NovaVpnTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Accent,
            onPrimary = Color(0xFF062019),
            background = Bg,
            surface = Panel,
            onSurface = Color(0xFFF3F8F5),
            onBackground = Color(0xFFF3F8F5),
            secondary = Warm,
            error = Danger
        ),
        content = content
    )
}

@Composable
private fun NovaVpnScreen(
    loggedIn: Boolean, apiUrl: String, onApiUrl: (String) -> Unit,
    username: String, onUsername: (String) -> Unit,
    loginPassword: String, onLoginPassword: (String) -> Unit,
    displayName: String, locations: List<Country>, selectedCode: String,
    connected: Boolean, busy: Boolean, status: String, error: String?,
    mustChangePassword: Boolean, oldPassword: String, onOldPassword: (String) -> Unit,
    newPassword: String, onNewPassword: (String) -> Unit,
    onLogin: () -> Unit, onChangePassword: () -> Unit, onSelect: (Country) -> Unit,
    onConnect: () -> Unit, onRefresh: () -> Unit, onLogout: () -> Unit
) {
    Surface(Modifier.fillMaxSize(), color = Bg) {
        when {
            !loggedIn -> LoginScreen(
                apiUrl, onApiUrl, username, onUsername, loginPassword, onLoginPassword,
                busy, status, error, onLogin
            )
            mustChangePassword -> PasswordSetupScreen(
                oldPassword, onOldPassword, newPassword, onNewPassword,
                busy, error, onChangePassword, onLogout
            )
            else -> {
                var selectedTab by remember { mutableStateOf(MainTab.HOME) }
                Scaffold(
                    containerColor = Bg,
                    bottomBar = {
                        NavigationBar(
                            containerColor = Color(0xFF0A1713),
                            contentColor = Color.White,
                            tonalElevation = 0.dp
                        ) {
                            NavigationBarItem(
                                selected = selectedTab == MainTab.HOME,
                                onClick = { selectedTab = MainTab.HOME },
                                icon = { Text("⌂", fontSize = 21.sp) },
                                label = { Text("Home", fontSize = 10.sp) },
                                colors = navColors()
                            )
                            NavigationBarItem(
                                selected = selectedTab == MainTab.LOCATIONS,
                                onClick = { selectedTab = MainTab.LOCATIONS },
                                icon = { Text("◎", fontSize = 21.sp) },
                                label = { Text("Locations", fontSize = 10.sp) },
                                colors = navColors()
                            )
                            NavigationBarItem(
                                selected = selectedTab == MainTab.SETTINGS,
                                onClick = { selectedTab = MainTab.SETTINGS },
                                icon = { Text("⚙", fontSize = 19.sp) },
                                label = { Text("Settings", fontSize = 10.sp) },
                                colors = navColors()
                            )
                        }
                    }
                ) { innerPadding ->
                    when (selectedTab) {
                        MainTab.HOME -> HomeScreen(
                            Modifier.padding(innerPadding), displayName, locations, selectedCode,
                            connected, busy, status, error, onConnect,
                            onOpenLocations = { selectedTab = MainTab.LOCATIONS },
                            onOpenSettings = { selectedTab = MainTab.SETTINGS }
                        )
                        MainTab.LOCATIONS -> LocationsScreen(
                            Modifier.padding(innerPadding), locations, selectedCode,
                            connected, busy, onSelect = {
                                onSelect(it)
                                selectedTab = MainTab.HOME
                            }
                        )
                        MainTab.SETTINGS -> SettingsScreen(
                            Modifier.padding(innerPadding), displayName, apiUrl = apiUrl,
                            connected = connected, busy = busy, status = status,
                            onRefresh = onRefresh, onLogout = onLogout,
                            onBackHome = { selectedTab = MainTab.HOME }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun navColors() = NavigationBarItemDefaults.colors(
    selectedIconColor = Accent,
    selectedTextColor = Mint,
    indicatorColor = Color(0xFF18372D),
    unselectedIconColor = Muted,
    unselectedTextColor = Muted
)

@Composable
private fun LoginScreen(
    apiUrl: String, onApiUrl: (String) -> Unit,
    username: String, onUsername: (String) -> Unit,
    password: String, onPassword: (String) -> Unit,
    busy: Boolean, status: String, error: String?, onLogin: () -> Unit
) {
    var showServerAddress by remember { mutableStateOf(apiUrl.isBlank()) }
    Column(
        Modifier.fillMaxSize()
            .background(Brush.verticalGradient(listOf(Color(0xFF17382C), Color(0xFF0B1B15), Bg)))
            .padding(horizontal = 24.dp)
            .padding(top = 34.dp, bottom = 24.dp)
            .verticalScroll(androidx.compose.foundation.rememberScrollState()),
        horizontalAlignment = Alignment.Start,
        verticalArrangement = Arrangement.Center
    ) {
        BrandHeader()
        Spacer(Modifier.height(54.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(7.dp).background(Accent, CircleShape))
            Spacer(Modifier.width(9.dp))
            Text("PRIVATE ACCESS", color = Mint, letterSpacing = 2.2.sp, fontSize = 10.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(15.dp))
        Text("Your network.\nYour own space.", color = Color(0xFFF4F8F5), fontSize = 39.sp, lineHeight = 43.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-1.2).sp)
        Spacer(Modifier.height(13.dp))
        Text("A secure connection, reserved for invited members.", color = Muted, fontSize = 14.sp, lineHeight = 21.sp)
        Spacer(Modifier.height(30.dp))
        Column(
            Modifier.fillMaxWidth().background(Panel.copy(alpha = 0.96f), RoundedCornerShape(24.dp))
                .border(1.dp, Line, RoundedCornerShape(24.dp)).padding(20.dp)
        ) {
            Text("SIGN IN", color = Warm, letterSpacing = 1.7.sp, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(18.dp))
            NovaField("EMAIL OR USERNAME", username, onUsername, hint = "Your private account", keyboard = KeyboardType.Email)
            Spacer(Modifier.height(13.dp))
            NovaField("PASSWORD", password, onPassword, hint = "Enter your password", password = true)
            if (showServerAddress) {
                Spacer(Modifier.height(13.dp))
                NovaField("PRIVATE NETWORK ADDRESS", apiUrl, onApiUrl, hint = "https://vpn.example.com", keyboard = KeyboardType.Uri)
                Text("Provided by your network administrator.", color = Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 6.dp))
            }
            TextButton(onClick = { showServerAddress = !showServerAddress }, contentPadding = PaddingValues(0.dp)) {
                Text(if (showServerAddress) "Hide connection settings" else "Connection settings", color = Muted, fontSize = 11.sp)
            }
            if (error != null) {
                Text(error, color = Danger, fontSize = 12.sp, lineHeight = 17.sp, modifier = Modifier.padding(vertical = 8.dp))
            }
            Button(
                onClick = onLogin,
                enabled = !busy && username.isNotBlank() && password.isNotBlank() && apiUrl.isNotBlank(),
                modifier = Modifier.fillMaxWidth().height(54.dp),
                shape = RoundedCornerShape(15.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color(0xFF062019)),
                elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp, pressedElevation = 2.dp)
            ) {
                if (busy) CircularProgressIndicator(Modifier.size(19.dp), color = Color(0xFF062019), strokeWidth = 2.dp)
                else Text("Continue securely", fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }
        }
        Spacer(Modifier.height(20.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("▣", color = Accent, fontSize = 15.sp)
            Spacer(Modifier.width(8.dp))
            Text("Private network · WireGuard protection", color = Muted, fontSize = 11.sp)
        }
        if (busy) Text(status, color = Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 10.dp))
    }
}

@Composable
private fun PasswordSetupScreen(
    oldPassword: String, onOldPassword: (String) -> Unit,
    newPassword: String, onNewPassword: (String) -> Unit,
    busy: Boolean, error: String?, onChangePassword: () -> Unit, onLogout: () -> Unit
) {
    Column(
        Modifier.fillMaxSize().background(Bg).padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        BrandHeader()
        Spacer(Modifier.height(42.dp))
        Text("ACCOUNT SECURITY", color = Warm, letterSpacing = 2.sp, fontSize = 10.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp))
        Text("Make it\nyours.", color = Color.White, fontSize = 43.sp, lineHeight = 46.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(12.dp))
        Text("Create a new password before connecting to your private network.", color = Muted, fontSize = 13.sp, lineHeight = 20.sp)
        Spacer(Modifier.height(28.dp))
        NovaField("TEMPORARY PASSWORD", oldPassword, onOldPassword, hint = "Current password", password = true)
        Spacer(Modifier.height(13.dp))
        NovaField("NEW PASSWORD · 12 CHARACTERS OR MORE", newPassword, onNewPassword, hint = "Create a strong password", password = true)
        if (error != null) Text(error, color = Danger, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
        Spacer(Modifier.height(18.dp))
        Button(onClick = onChangePassword, enabled = !busy && oldPassword.isNotBlank() && newPassword.length >= 12,
            modifier = Modifier.fillMaxWidth().height(54.dp), shape = RoundedCornerShape(15.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color(0xFF062019))) {
            Text(if (busy) "Updating…" else "Save new password", fontWeight = FontWeight.Bold)
        }
        TextButton(onClick = onLogout, modifier = Modifier.align(Alignment.CenterHorizontally)) { Text("Sign out", color = Muted) }
    }
}

@Composable
private fun HomeScreen(
    modifier: Modifier, displayName: String, locations: List<Country>, selectedCode: String,
    connected: Boolean, busy: Boolean, status: String, error: String?, onConnect: () -> Unit,
    onOpenLocations: () -> Unit, onOpenSettings: () -> Unit
) {
    val selected = locations.firstOrNull { it.code == selectedCode }
    LazyColumn(
        modifier.fillMaxSize().background(Bg),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 22.dp, bottom = 26.dp),
        verticalArrangement = Arrangement.spacedBy(17.dp)
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                BrandHeader(Modifier.weight(1f))
                TextButton(onClick = onOpenSettings) {
                    Text("⚙", color = Muted, fontSize = 21.sp)
                }
            }
        }
        item {
            Column {
                Text("PRIVATE NETWORK", color = Mint, fontSize = 10.sp, letterSpacing = 2.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(7.dp))
                Text("Welcome, ${displayName.ifBlank { "Member" }}", color = Color(0xFFF3F8F5), fontSize = 26.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.5).sp)
                Text("Your connection, under your control.", color = Muted, fontSize = 13.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }
        item {
            Column(
                Modifier.fillMaxWidth().background(
                    Brush.linearGradient(listOf(Color(0xFF183B30), Color(0xFF10251F), Color(0xFF101D19))),
                    RoundedCornerShape(26.dp)
                ).border(1.dp, Color(0xFF315847), RoundedCornerShape(26.dp)).padding(20.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).background(if (connected) Accent else Warm, CircleShape))
                    Spacer(Modifier.width(8.dp))
                    Text("CONNECTION STATUS", color = Muted, letterSpacing = 1.5.sp, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.weight(1f))
                    Text("WIREGUARD", color = Mint, fontSize = 9.sp, letterSpacing = 1.1.sp, fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.height(18.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(if (connected) "You’re protected" else if (busy) "Connecting" else "Not connected",
                            color = Color(0xFFF4F8F5), fontSize = 24.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.7).sp)
                        Spacer(Modifier.height(6.dp))
                        Text(if (connected) "Your traffic is routed through your selected VPN server." else "Connect to protect your internet connection.",
                            color = Muted, fontSize = 11.sp, lineHeight = 16.sp)
                    }
                    Box(
                        Modifier.size(86.dp).background(
                            Brush.radialGradient(listOf(if (connected) Color(0xFF8BF0C9) else Color(0xFF386C56), Color(0x001B3A2D))), CircleShape
                        ).border(1.dp, Color(0xFF70D9AE).copy(alpha = 0.45f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        if (busy) CircularProgressIndicator(Modifier.size(32.dp), color = Mint, strokeWidth = 2.dp)
                        else Text(if (connected) "✓" else "⏻", color = Mint, fontSize = 35.sp, fontWeight = FontWeight.Light)
                    }
                }
                Spacer(Modifier.height(20.dp))
                Button(
                    onClick = onConnect,
                    enabled = !busy && (connected || selected?.available == true),
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    shape = RoundedCornerShape(15.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (connected) Color(0xFF243A32) else Accent,
                        contentColor = if (connected) Color.White else Color(0xFF062019),
                        disabledContainerColor = Color(0xFF263831), disabledContentColor = Muted
                    ),
                    elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
                ) {
                    Text(if (busy) "Please wait…" else if (connected) "Disconnect" else "Connect securely", fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
                if (error != null) Text(error, color = Danger, fontSize = 11.sp, lineHeight = 16.sp, modifier = Modifier.padding(top = 10.dp))
                else Text(status, color = Muted, fontSize = 10.sp, lineHeight = 15.sp, modifier = Modifier.padding(top = 10.dp))
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricCard(Modifier.weight(1f), "LOCATIONS", "${locations.size}", "Country slots")
                MetricCard(Modifier.weight(1f), "AVAILABLE TO YOU", "${locations.count { it.available }}", "Assigned servers")
            }
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Your location", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Text("Choose where your connection exits.", color = Muted, fontSize = 11.sp)
                }
                TextButton(onClick = onOpenLocations) { Text("View all  →", color = Mint, fontSize = 12.sp) }
            }
        }
        if (selected != null) {
            item { SelectedLocationCard(selected, connected, onOpenLocations) }
        } else {
            item { EmptyStateCard("No location assigned", "Your administrator has not assigned a VPN location to this account yet.") }
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Private by design", color = Warm, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.width(8.dp))
                Text("·", color = Muted)
                Spacer(Modifier.width(8.dp))
                Text("Access managed by your administrator", color = Muted, fontSize = 10.sp)
            }
        }
    }
}

@Composable
private fun MetricCard(modifier: Modifier, label: String, value: String, caption: String) {
    Column(modifier.background(Panel, RoundedCornerShape(17.dp)).border(1.dp, Line, RoundedCornerShape(17.dp)).padding(15.dp)) {
        Text(label, color = Muted, fontSize = 8.sp, letterSpacing = 1.1.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(value, color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.SemiBold)
        Text(caption, color = Muted, fontSize = 10.sp)
    }
}

@Composable
private fun SelectedLocationCard(country: Country, connected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(18.dp)).border(1.dp, Line, RoundedCornerShape(18.dp))
            .clickable(onClick = onClick).padding(15.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(48.dp).background(PanelSoft, RoundedCornerShape(14.dp)), contentAlignment = Alignment.Center) {
            Text(country.flag, fontSize = 27.sp)
        }
        Spacer(Modifier.width(13.dp))
        Column(Modifier.weight(1f)) {
            Text(country.name, color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Text(country.region, color = Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 3.dp))
        }
        Column(horizontalAlignment = Alignment.End) {
            Text(if (connected) "CONNECTED" else if (country.available) "ACCESS ENABLED" else "LOCKED",
                color = if (connected || country.available) Mint else Muted, fontSize = 8.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.7.sp)
            Text("Change  ›", color = Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 5.dp))
        }
    }
}

@Composable
private fun LocationsScreen(
    modifier: Modifier, locations: List<Country>, selectedCode: String,
    connected: Boolean, busy: Boolean, onSelect: (Country) -> Unit
) {
    var query by remember { mutableStateOf("") }
    val filtered = locations.filter { it.name.contains(query, ignoreCase = true) || it.region.contains(query, ignoreCase = true) }
    LazyColumn(
        modifier.fillMaxSize().background(Bg),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 24.dp, bottom = 25.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text("LOCATIONS", color = Mint, fontSize = 10.sp, letterSpacing = 2.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(7.dp))
            Text("Choose your destination.", color = Color.White, fontSize = 25.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.6).sp)
            Text("Your private network across five countries.", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp, bottom = 7.dp))
            OutlinedTextField(
                value = query, onValueChange = { query = it }, modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Search locations", color = Muted, fontSize = 13.sp) },
                leadingIcon = { Text("⌕", color = Muted, fontSize = 22.sp) },
                singleLine = true, shape = RoundedCornerShape(15.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Accent, unfocusedBorderColor = Line,
                    focusedTextColor = Color.White, unfocusedTextColor = Color.White,
                    cursorColor = Mint, focusedContainerColor = Panel, unfocusedContainerColor = Panel
                )
            )
        }
        item {
            Row(Modifier.fillMaxWidth().padding(top = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("ALL COUNTRIES", color = Muted, fontSize = 9.sp, letterSpacing = 1.3.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.weight(1f))
                Text("${locations.count { it.available }} ACCESSIBLE", color = Mint, fontSize = 9.sp, fontWeight = FontWeight.Bold)
            }
        }
        items(filtered, key = { it.code }) { country ->
            val selected = country.code == selectedCode
            Row(
                Modifier.fillMaxWidth()
                    .background(if (selected) Color(0xFF142C23) else Panel, RoundedCornerShape(18.dp))
                    .border(if (selected) 1.dp else 1.dp, if (selected) Color(0xFF5CBF97) else Line, RoundedCornerShape(18.dp))
                    .clickable(enabled = country.available && !connected && !busy) { onSelect(country) }
                    .padding(15.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(Modifier.size(48.dp).background(PanelSoft, RoundedCornerShape(14.dp)), contentAlignment = Alignment.Center) {
                    Text(country.flag, fontSize = 27.sp)
                }
                Spacer(Modifier.width(13.dp))
                Column(Modifier.weight(1f)) {
                    Text(country.name, color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                    Text(country.region, color = Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 3.dp))
                    Text(if (country.available) "Access enabled for your account" else "Not assigned to your account",
                        color = if (country.available) Mint else Muted, fontSize = 9.sp, modifier = Modifier.padding(top = 6.dp))
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(if (selected) "SELECTED" else if (country.available) "ACCESS" else "LOCKED",
                        color = if (selected || country.available) Mint else Muted, fontSize = 8.sp, fontWeight = FontWeight.Bold)
                    if (selected) Text("✓", color = Mint, fontSize = 18.sp, modifier = Modifier.padding(top = 5.dp))
                    else if (!country.available) Text("⌑", color = Muted, fontSize = 17.sp, modifier = Modifier.padding(top = 5.dp))
                }
            }
        }
        if (filtered.isEmpty()) item { EmptyStateCard("No matching location", "Try searching by country or region name.") }
        if (connected) item { Text("Disconnect before changing your VPN location.", color = Warm, fontSize = 11.sp, modifier = Modifier.padding(top = 5.dp)) }
        if (busy) item { LinearProgressIndicator(Modifier.fillMaxWidth(), color = Accent, trackColor = PanelSoft) }
    }
}

@Composable
private fun SettingsScreen(
    modifier: Modifier, displayName: String, apiUrl: String, connected: Boolean, busy: Boolean,
    status: String, onRefresh: () -> Unit, onLogout: () -> Unit, onBackHome: () -> Unit
) {
    Column(
        modifier.fillMaxSize().background(Bg).verticalScroll(androidx.compose.foundation.rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 24.dp)
    ) {
        Text("PREFERENCES", color = Mint, fontSize = 10.sp, letterSpacing = 2.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(7.dp))
        Text("Settings", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.SemiBold)
        Text("Your account and connection details.", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp, bottom = 20.dp))
        Column(Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(20.dp)).border(1.dp, Line, RoundedCornerShape(20.dp)).padding(17.dp)) {
            Text("ACCOUNT", color = Warm, fontSize = 9.sp, letterSpacing = 1.5.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(14.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(45.dp).background(PanelSoft, CircleShape), contentAlignment = Alignment.Center) {
                    Text(displayName.take(1).uppercase().ifBlank { "N" }, color = Mint, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(displayName.ifBlank { "Private member" }, color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                    Text("Private network member", color = Muted, fontSize = 10.sp)
                }
            }
            Divider(color = Line, modifier = Modifier.padding(vertical = 15.dp))
            SettingsRow("Connection", if (connected) "Connected" else "Disconnected", connected)
            SettingsRow("Protocol", "WireGuard", true)
            SettingsRow("Account access", "Private invitation", null)
        }
        Spacer(Modifier.height(14.dp))
        Column(Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(20.dp)).border(1.dp, Line, RoundedCornerShape(20.dp)).padding(17.dp)) {
            Text("NETWORK", color = Warm, fontSize = 9.sp, letterSpacing = 1.5.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))
            Text("Control server", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Text(apiUrl, color = Muted, fontSize = 10.sp, lineHeight = 15.sp, modifier = Modifier.padding(top = 4.dp))
            Text("VPN profiles are stored encrypted on this device.", color = Muted, fontSize = 10.sp, lineHeight = 15.sp, modifier = Modifier.padding(top = 12.dp))
            OutlinedButton(onClick = onRefresh, enabled = !busy, modifier = Modifier.fillMaxWidth().padding(top = 13.dp).height(46.dp),
                shape = RoundedCornerShape(13.dp), border = androidx.compose.foundation.BorderStroke(1.dp, Line),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Mint)) {
                Text(if (busy) "Refreshing…" else "Refresh locations", fontWeight = FontWeight.SemiBold)
            }
            val settingsContext = androidx.compose.ui.platform.LocalContext.current
            Text("City names are labels: each country uses one server, so your exit address is in that country.", color = Muted, fontSize = 10.sp, lineHeight = 15.sp, modifier = Modifier.padding(top = 14.dp))
            Text("Kill switch: in Android VPN settings, turn on Always-on VPN and Block connections without VPN for this app.", color = Muted, fontSize = 10.sp, lineHeight = 15.sp, modifier = Modifier.padding(top = 10.dp))
            OutlinedButton(onClick = { try { settingsContext.startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) } catch (_: Exception) { } },
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp).height(46.dp),
                shape = RoundedCornerShape(13.dp), border = androidx.compose.foundation.BorderStroke(1.dp, Line),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Mint)) {
                Text("Open Android VPN settings", fontWeight = FontWeight.SemiBold)
            }
        }
        Spacer(Modifier.height(14.dp))
        Column(Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(20.dp)).border(1.dp, Line, RoundedCornerShape(20.dp)).padding(17.dp)) {
            Text("ABOUT PRIVATE VPN", color = Warm, fontSize = 9.sp, letterSpacing = 1.5.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            SettingsRow("Protection", "WireGuard tunnel", true)
            SettingsRow("Access", "Private invitation only", true)
            SettingsRow("Version", "1.2.1", null)
        }
        Spacer(Modifier.height(20.dp))
        Button(onClick = onBackHome, modifier = Modifier.fillMaxWidth().height(49.dp), shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = PanelSoft, contentColor = Color.White)) {
            Text("Back to home", fontWeight = FontWeight.SemiBold)
        }
        OutlinedButton(onClick = onLogout, modifier = Modifier.fillMaxWidth().padding(top = 9.dp).height(49.dp),
            shape = RoundedCornerShape(14.dp), border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF70404A)),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Danger)) {
            Text("Sign out", fontWeight = FontWeight.SemiBold)
        }
        Text(status, color = Muted, fontSize = 9.sp, modifier = Modifier.align(Alignment.CenterHorizontally).padding(top = 13.dp))
    }
}

@Composable
private fun SettingsRow(label: String, value: String, positive: Boolean?) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Muted, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text(value, color = when (positive) { true -> Mint; false -> Warm; null -> Color.White }, fontSize = 11.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun EmptyStateCard(title: String, message: String) {
    Column(Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(18.dp)).border(1.dp, Line, RoundedCornerShape(18.dp)).padding(18.dp)) {
        Text(title, color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
        Text(message, color = Muted, fontSize = 10.sp, lineHeight = 15.sp, modifier = Modifier.padding(top = 5.dp))
    }
}

@Composable
private fun BrandHeader(modifier: Modifier = Modifier) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.foundation.Image(
            painter = androidx.compose.ui.res.painterResource(id = R.drawable.ic_pv_logo),
            contentDescription = "PRIVATE VPN",
            modifier = Modifier.size(43.dp)
        )
        Spacer(Modifier.width(11.dp))
        Column {
            Text("PRIVATE VPN", fontSize = 21.sp, fontWeight = FontWeight.SemiBold, color = Color.White, letterSpacing = (-0.5).sp)
            Text("PRIVATE NETWORK", fontSize = 8.sp, letterSpacing = 1.9.sp, color = Muted, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun NovaField(
    label: String, value: String, onValue: (String) -> Unit,
    hint: String, password: Boolean = false, keyboard: KeyboardType = KeyboardType.Text
) {
    Column {
        Text(label, color = Muted, fontSize = 9.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.2.sp)
        Spacer(Modifier.height(7.dp))
        OutlinedTextField(
            value = value, onValueChange = onValue, modifier = Modifier.fillMaxWidth(),
            placeholder = { Text(hint, color = Muted.copy(alpha = 0.65f), fontSize = 12.sp) },
            singleLine = true, shape = RoundedCornerShape(13.dp),
            visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
            keyboardOptions = KeyboardOptions(keyboardType = if (password) KeyboardType.Password else keyboard),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Accent, unfocusedBorderColor = Line,
                focusedTextColor = Color.White, unfocusedTextColor = Color.White,
                cursorColor = Mint, focusedContainerColor = Color(0xFF091510), unfocusedContainerColor = Color(0xFF091510)
            )
        )
    }
}

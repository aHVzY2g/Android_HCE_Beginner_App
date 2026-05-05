package de.androidcrypto.android_hce_beginner_app.homekey;

import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import de.androidcrypto.android_hce_beginner_app.R;

/**
 * Main UI for the Apple Home Key emulator.
 *
 * Shows:
 *  - NFC / HCE readiness status
 *  - Device long-term public key (65-byte uncompressed, hex)
 *  - Device identifier (6-byte random ID sent as tag 0x4E in STANDARD AUTH)
 *  - "Copy Enrollment JSON" button — copies the JSON payload for the ESP32
 *    /api/android/enroll endpoint so the reader can verify signatures
 *  - Live transaction log broadcast from HomeKeyHceService
 */
public class HomeKeyActivity extends AppCompatActivity {

    public static final String ACTION_NFC_STATUS = "de.androidcrypto.homekey.NFC_STATUS";
    public static final String EXTRA_STATUS      = "status";

    private TextView   tvStatus;
    private TextView   tvPubKey;
    private TextView   tvDeviceId;
    private TextView   tvLog;
    private ScrollView scrollLog;

    private HomeKeyCrypto crypto;
    private final StringBuilder logBuffer = new StringBuilder();

    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            String msg = intent.getStringExtra(EXTRA_STATUS);
            if (msg != null) appendLog(msg);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_home_key);

        tvStatus   = findViewById(R.id.tv_hk_status);
        tvPubKey   = findViewById(R.id.tv_hk_pubkey);
        tvDeviceId = findViewById(R.id.tv_hk_device_id);
        tvLog      = findViewById(R.id.tv_hk_log);
        scrollLog  = findViewById(R.id.scroll_log);

        crypto = new HomeKeyCrypto(this);
        refreshKeyInfo();
        checkNfc();

        Button btnRegen = findViewById(R.id.btn_hk_regen);
        btnRegen.setOnClickListener(v -> {
            crypto.generateDeviceKey();
            refreshKeyInfo();
            appendLog("New device key pair generated");
        });

        Button btnCopy = findViewById(R.id.btn_hk_copy_enrollment);
        btnCopy.setOnClickListener(v -> copyEnrollmentJson());
    }

    @Override
    protected void onResume() {
        super.onResume();
        registerReceiver(receiver, new IntentFilter(ACTION_NFC_STATUS));
    }

    @Override
    protected void onPause() {
        super.onPause();
        unregisterReceiver(receiver);
    }

    // -------------------------------------------------------------------------

    private void refreshKeyInfo() {
        byte[] pub = crypto.getDevicePublicKeyBytes();
        byte[] id  = crypto.getDeviceIdentifier();

        if (pub == null) {
            tvPubKey.setText("Device Public Key: unavailable");
        } else {
            String hex = HomeKeyCrypto.toHex(pub);
            tvPubKey.setText("Device Public Key (65 bytes):\n"
                    + hex.substring(0, 44) + "\n"
                    + (hex.length() > 44  ? hex.substring(44,  Math.min(88,  hex.length())) + "\n" : "")
                    + (hex.length() > 88  ? hex.substring(88,  Math.min(130, hex.length())) + "\n" : "")
                    + (hex.length() > 130 ? hex.substring(130) : ""));
        }

        if (id == null) {
            tvDeviceId.setText("Device ID (endpoint_id): unavailable");
        } else {
            tvDeviceId.setText("Device ID (endpoint_id): " + HomeKeyCrypto.toHex(id));
        }
    }

    private void copyEnrollmentJson() {
        byte[] pub = crypto.getDevicePublicKeyBytes();
        byte[] id  = crypto.getDeviceIdentifier();
        if (pub == null || id == null) {
            Toast.makeText(this, "Key not ready", Toast.LENGTH_SHORT).show();
            return;
        }
        String json = "{\"public_key\":\"" + HomeKeyCrypto.toHex(pub)
                + "\",\"endpoint_id\":\"" + HomeKeyCrypto.toHex(id) + "\"}";
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("HomeKey Enrollment", json));
        Toast.makeText(this, "Enrollment JSON copied to clipboard", Toast.LENGTH_SHORT).show();
        appendLog("Copied enrollment JSON for endpoint_id " + HomeKeyCrypto.toHex(id));
    }

    private void checkNfc() {
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null) {
            tvStatus.setText("Status: NFC not supported on this device");
        } else if (!adapter.isEnabled()) {
            tvStatus.setText("Status: NFC is disabled - enable it in Settings");
        } else {
            tvStatus.setText("Status: Ready - hold phone near a Home Key reader");
        }
    }

    private void appendLog(String msg) {
        logBuffer.insert(0, msg + "\n");
        if (logBuffer.length() > 3000) logBuffer.setLength(3000);
        runOnUiThread(() -> {
            tvLog.setText(logBuffer.toString());
            scrollLog.fullScroll(ScrollView.FOCUS_UP);
        });
    }
}

package de.androidcrypto.android_hce_beginner_app.homekey;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import de.androidcrypto.android_hce_beginner_app.R;

public class HomeKeyActivity extends AppCompatActivity {

    public static final String ACTION_NFC_STATUS = "de.androidcrypto.homekey.NFC_STATUS";
    public static final String EXTRA_STATUS      = "status";

    private TextView   tvStatus;
    private TextView   tvPubKey;
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

        tvStatus  = findViewById(R.id.tv_hk_status);
        tvPubKey  = findViewById(R.id.tv_hk_pubkey);
        tvLog     = findViewById(R.id.tv_hk_log);
        scrollLog = findViewById(R.id.scroll_log);

        crypto = new HomeKeyCrypto(this);
        refreshPubKey();
        checkNfc();

        Button btnRegen = findViewById(R.id.btn_hk_regen);
        btnRegen.setOnClickListener(v -> {
            crypto.generateDeviceKey();
            refreshPubKey();
            appendLog("New device key pair generated");
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter filter = new IntentFilter(ACTION_NFC_STATUS);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(receiver, filter);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        unregisterReceiver(receiver);
    }

    private void refreshPubKey() {
        byte[] pub = crypto.getDevicePublicKeyBytes();
        if (pub == null) { tvPubKey.setText("Device Public Key: unavailable"); return; }
        String hex = HomeKeyCrypto.toHex(pub);
        String line1 = hex.substring(0, Math.min(44, hex.length()));
        String line2 = hex.length() > 44 ? hex.substring(44, Math.min(88, hex.length())) : "";
        String line3 = hex.length() > 88 ? hex.substring(88) : "";
        tvPubKey.setText("Device Public Key (share with reader):\n" + line1 + "\n" + line2 + "\n" + line3);
    }

    private void checkNfc() {
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null)
            tvStatus.setText("Status: NFC not supported on this device");
        else if (!adapter.isEnabled())
            tvStatus.setText("Status: NFC is disabled - enable it in Settings");
        else
            tvStatus.setText("Status: Ready - hold phone near a Home Key reader");
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

package de.androidcrypto.android_hce_beginner_app;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import android.widget.Button;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import de.androidcrypto.android_hce_beginner_app.homekey.HomeKeyActivity;

public class HomeFragment extends Fragment {

    private static final String ARG_PARAM1 = "param1";
    private static final String ARG_PARAM2 = "param2";

    private String mParam1;
    private String mParam2;

    public HomeFragment() {}

    public static HomeFragment newInstance(String param1, String param2) {
        HomeFragment fragment = new HomeFragment();
        Bundle args = new Bundle();
        args.putString(ARG_PARAM1, param1);
        args.putString(ARG_PARAM2, param2);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mParam1 = getArguments().getString(ARG_PARAM1);
            mParam2 = getArguments().getString(ARG_PARAM2);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_home, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Button btnOpenHomeKey = view.findViewById(R.id.btnOpenHomeKey);
        btnOpenHomeKey.setOnClickListener(v ->
                startActivity(new Intent(requireContext(), HomeKeyActivity.class)));

        Button btnLicenses = view.findViewById(R.id.btnLicenses);
        btnLicenses.setOnClickListener(v -> displayLicensesAlertDialog());
    }

    private void displayLicensesAlertDialog() {
        WebView webView = (WebView) LayoutInflater.from(getContext())
                .inflate(R.layout.dialog_licenses, null);
        webView.loadUrl("file:///android_asset/open_source_licenses.html");
        new android.app.AlertDialog.Builder(getContext(), R.style.Theme_Android_HCE_Beginner_App)
                .setTitle(getString(R.string.action_licenses))
                .setView(webView)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }
}

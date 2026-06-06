package com.phishingdetector.ui.home;

import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.google.android.material.chip.Chip;
import com.phishingdetector.R;
import com.phishingdetector.databinding.ActivityHomeBinding;
import com.phishingdetector.network.DetectionResponse;
import com.phishingdetector.ui.results.ResultsActivity;
import com.phishingdetector.ui.results.ResultsAdapter;

public class HomeActivity extends AppCompatActivity {

    private ActivityHomeBinding binding;
    private HomeViewModel viewModel;
    private ResultsAdapter recentAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityHomeBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        setSupportActionBar(binding.toolbar);

        viewModel = new ViewModelProvider(this).get(HomeViewModel.class);

        setupRecyclerView();
        setupObservers();
        setupClickListeners();
        updateServiceStatus();
        requestNotificationPermission();
    }

    @Override
    protected void onResume() {
        super.onResume();
        viewModel.refreshHistory();
        updateServiceStatus();
    }

    // ── UI setup ─────────────────────────────────────────────────────────────

    private void setupRecyclerView() {
        recentAdapter = new ResultsAdapter();
        binding.recyclerRecent.setLayoutManager(new LinearLayoutManager(this));
        binding.recyclerRecent.setAdapter(recentAdapter);
    }

    private void setupObservers() {
        viewModel.getScanState().observe(this, state -> {
            switch (state) {
                case LOADING:
                    binding.progressBar.setVisibility(View.VISIBLE);
                    binding.btnScan.setEnabled(false);
                    break;
                case SUCCESS:
                    binding.progressBar.setVisibility(View.GONE);
                    binding.btnScan.setEnabled(true);
                    break;
                case ERROR:
                    binding.progressBar.setVisibility(View.GONE);
                    binding.btnScan.setEnabled(true);
                    break;
                default:
                    binding.progressBar.setVisibility(View.GONE);
                    binding.btnScan.setEnabled(true);
            }
        });

        viewModel.getScanResult().observe(this, this::showScanResult);

        viewModel.getErrorMsg().observe(this, msg -> {
            if (!TextUtils.isEmpty(msg)) {
                Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
            }
        });

        viewModel.getHistory().observe(this, results -> {
            recentAdapter.submitList(results);
            binding.tvNoHistory.setVisibility(
                    results.isEmpty() ? View.VISIBLE : View.GONE);
        });
    }

    private void setupClickListeners() {
        binding.btnScan.setOnClickListener(v ->
                viewModel.scanUrl(binding.etUrl.getText().toString()));

        binding.switchService.setChecked(viewModel.isServiceEnabled());
        binding.switchService.setOnCheckedChangeListener((btn, checked) -> {
            viewModel.setServiceEnabled(checked);
            updateServiceStatus();
        });

        binding.btnViewAll.setOnClickListener(v ->
                startActivity(new Intent(this, ResultsActivity.class)));

        binding.cardNotificationPerm.setOnClickListener(v ->
                startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)));

        binding.cardAccessibilityPerm.setOnClickListener(v ->
                startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)));
    }

    // ── Service status ────────────────────────────────────────────────────────

    private void updateServiceStatus() {
        boolean notifEnabled = isNotificationListenerEnabled();
        boolean accessEnabled = isAccessibilityServiceEnabled();
        boolean monitorOn = viewModel.isServiceEnabled();

        binding.chipNotif.setText(notifEnabled
                ? R.string.status_notif_on : R.string.status_notif_off);
        binding.chipNotif.setChipBackgroundColorResource(notifEnabled
                ? R.color.safe_green : R.color.phishing_red);

        binding.chipAccess.setText(accessEnabled
                ? R.string.status_access_on : R.string.status_access_off);
        binding.chipAccess.setChipBackgroundColorResource(accessEnabled
                ? R.color.safe_green : R.color.phishing_red);

        binding.cardNotificationPerm.setVisibility(notifEnabled ? View.GONE : View.VISIBLE);
        binding.cardAccessibilityPerm.setVisibility(accessEnabled ? View.GONE : View.VISIBLE);

        binding.switchService.setChecked(monitorOn);
    }

    private boolean isNotificationListenerEnabled() {
        String flat = Settings.Secure.getString(
                getContentResolver(), "enabled_notification_listeners");
        return flat != null && flat.contains(
                new ComponentName(this,
                        com.phishingdetector.notification.PhishingNotificationService.class)
                        .flattenToString());
    }

    private boolean isAccessibilityServiceEnabled() {
        String flat = Settings.Secure.getString(
                getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        return flat != null && flat.contains(
                new ComponentName(this,
                        com.phishingdetector.accessibility.PhishingAccessibilityService.class)
                        .flattenToString());
    }

    // ── Scan result ───────────────────────────────────────────────────────────

    private void showScanResult(DetectionResponse result) {
        if (result == null) return;
        int pct = (int) (result.getConfidence() * 100);
        String msg = result.isPhishing()
                ? getString(R.string.result_phishing, pct)
                : getString(R.string.result_safe, pct);
        new AlertDialog.Builder(this)
                .setTitle(result.isPhishing()
                        ? R.string.result_title_phishing : R.string.result_title_safe)
                .setMessage(msg)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    // ── Options menu ─────────────────────────────────────────────────────────

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_home, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            showApiUrlDialog();
            return true;
        } else if (id == R.id.action_clear_history) {
            viewModel.clearHistory();
            Toast.makeText(this, R.string.history_cleared, Toast.LENGTH_SHORT).show();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void showApiUrlDialog() {
        EditText input = new EditText(this);
        input.setText(viewModel.getApiUrl());
        input.setSingleLine(true);

        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_api_url_title)
                .setView(input)
                .setPositiveButton(android.R.string.ok, (d, w) -> {
                    String url = input.getText().toString().trim();
                    if (!url.isEmpty()) {
                        if (!url.endsWith("/")) url += "/";
                        viewModel.saveApiUrl(url);
                        Toast.makeText(this, R.string.api_url_saved, Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    // ── Permissions ───────────────────────────────────────────────────────────

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(
                    new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 0);
        }
    }
}

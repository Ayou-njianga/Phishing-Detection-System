package com.phishingdetector.ui.results;

import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.phishingdetector.R;
import com.phishingdetector.databinding.ActivityResultsBinding;
import com.phishingdetector.ui.home.HomeViewModel;

public class ResultsActivity extends AppCompatActivity {

    private ActivityResultsBinding binding;
    private HomeViewModel viewModel;
    private ResultsAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityResultsBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        setSupportActionBar(binding.toolbar);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle(R.string.title_results);
        }

        viewModel = new ViewModelProvider(this).get(HomeViewModel.class);

        adapter = new ResultsAdapter();
        binding.recyclerResults.setLayoutManager(new LinearLayoutManager(this));
        binding.recyclerResults.setAdapter(adapter);

        viewModel.getHistory().observe(this, results -> {
            adapter.submitList(results);
            binding.tvEmpty.setVisibility(results.isEmpty() ? View.VISIBLE : View.GONE);
        });

        binding.fabClear.setOnClickListener(v -> viewModel.clearHistory());
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            onBackPressed();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}

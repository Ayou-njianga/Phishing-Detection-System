package com.phishingdetector.ui.results;

import android.view.LayoutInflater;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.ListAdapter;
import androidx.recyclerview.widget.RecyclerView;

import android.content.res.ColorStateList;

import com.phishingdetector.R;
import com.phishingdetector.databinding.ItemResultBinding;
import com.phishingdetector.network.DetectionResult;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class ResultsAdapter extends ListAdapter<DetectionResult, ResultsAdapter.ViewHolder> {

    private static final SimpleDateFormat DATE_FMT =
            new SimpleDateFormat("MMM d, HH:mm", Locale.getDefault());

    public ResultsAdapter() {
        super(DIFF_CALLBACK);
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        ItemResultBinding binding = ItemResultBinding.inflate(
                LayoutInflater.from(parent.getContext()), parent, false);
        return new ViewHolder(binding);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        holder.bind(getItem(position));
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        private final ItemResultBinding binding;

        ViewHolder(ItemResultBinding binding) {
            super(binding.getRoot());
            this.binding = binding;
        }

        void bind(DetectionResult result) {
            android.content.Context ctx = binding.getRoot().getContext();
            binding.tvUrl.setText(result.getUrl());
            binding.tvTimestamp.setText(DATE_FMT.format(new Date(result.getTimestamp())));

            int pct = (int) (result.getConfidence() * 100);
            int colorRes = result.isPhishing() ? R.color.phishing_red : R.color.safe_green;
            int colorInt = ContextCompat.getColor(ctx, colorRes);

            if (result.isPhishing()) {
                binding.chipStatus.setText(ctx.getString(R.string.label_phishing, pct));
            } else {
                binding.chipStatus.setText(ctx.getString(R.string.label_safe, pct));
            }
            binding.chipStatus.setChipBackgroundColor(ColorStateList.valueOf(colorInt));
            binding.cardItem.setStrokeColor(ColorStateList.valueOf(colorInt));

            String source = result.getDetectionSource();
            binding.tvSource.setText(source != null ? source : "—");
        }
    }

    private static final DiffUtil.ItemCallback<DetectionResult> DIFF_CALLBACK =
            new DiffUtil.ItemCallback<DetectionResult>() {
                @Override
                public boolean areItemsTheSame(@NonNull DetectionResult a,
                                               @NonNull DetectionResult b) {
                    return a.getUrl().equals(b.getUrl())
                            && a.getTimestamp() == b.getTimestamp();
                }

                @Override
                public boolean areContentsTheSame(@NonNull DetectionResult a,
                                                  @NonNull DetectionResult b) {
                    return a.isPhishing() == b.isPhishing()
                            && a.getConfidence() == b.getConfidence();
                }
            };
}

"""Tests for model build and prediction."""
import numpy as np
import pytest


class TestModelBuild:
    def test_model_compiles(self):
        from src.model.neural_net import build_model
        model = build_model(input_dim=36)
        assert model is not None

    def test_model_output_shape(self):
        from src.model.neural_net import build_model
        model = build_model(input_dim=36)
        dummy = np.random.rand(10, 36).astype(np.float32)
        out = model.predict(dummy, verbose=0)
        assert out.shape == (10, 1)

    def test_model_output_range(self):
        from src.model.neural_net import build_model
        model = build_model(input_dim=36)
        dummy = np.random.rand(100, 36).astype(np.float32)
        out = model.predict(dummy, verbose=0).flatten()
        assert out.min() >= 0.0
        assert out.max() <= 1.0

    def test_custom_architecture(self):
        from src.model.neural_net import build_model
        model = build_model(input_dim=20, hidden_layers=[64, 32], dropout_rate=0.2)
        assert len(model.layers) > 4

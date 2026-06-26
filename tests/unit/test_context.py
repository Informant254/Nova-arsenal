"""
Tests for Nova-Arsenal Context Compression (DSA, HCA, CSA).
"""

import pytest


class TestDSAConfig:
    def test_default_config(self):
        from nova_arsenal.context.compression import DSAConfig

        cfg = DSAConfig()
        assert cfg.compressed_latent_dim == 256
        assert cfg.top_k == 2048
        assert cfg.deterministic_topk is True

    def test_custom_config(self):
        from nova_arsenal.context.compression import DSAConfig

        cfg = DSAConfig(compressed_latent_dim=128, top_k=1024)
        assert cfg.compressed_latent_dim == 128
        assert cfg.top_k == 1024


class TestDSAIndexer:
    def test_initialization(self):
        from nova_arsenal.context.compression import DSAIndexer

        indexer = DSAIndexer()
        assert indexer.top_k == 2048

    def test_score_segments(self):
        from nova_arsenal.context.compression import DSAIndexer

        indexer = DSAIndexer(top_k=5)
        # score_segments expects embeddings, not strings
        # Use score_segments_by_keywords from ContentCompressor instead
        query_emb = [1.0, 0.0, 0.0]
        segment_embs = [
            [1.0, 0.0, 0.0],  # high similarity
            [0.0, 1.0, 0.0],  # low similarity
            [0.9, 0.1, 0.0],  # medium similarity
        ]
        scores = indexer.score_segments(query_emb, segment_embs)
        assert len(scores) == 3
        assert scores[0][1] > scores[1][1]  # first segment scores higher


class TestContentCompressor:
    def test_initialization(self):
        from nova_arsenal.context.compression import ContentCompressor

        comp = ContentCompressor()
        assert hasattr(comp, "compress")

    def test_compress_basic(self):
        from nova_arsenal.context.compression import ContentCompressor

        comp = ContentCompressor()
        result = comp.compress(
            content="This is a test document with some content.",
            query_keywords=["test"],
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_compress_empty(self):
        from nova_arsenal.context.compression import ContentCompressor

        comp = ContentCompressor()
        result = comp.compress(content="", query_keywords=[])
        assert isinstance(result, str)

    def test_compress_long_content(self):
        from nova_arsenal.context.compression import ContentCompressor

        comp = ContentCompressor()
        long_content = "Line with various keywords. " * 1000
        result = comp.compress(
            content=long_content,
            query_keywords=["keyword"],
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_compress_security_content(self):
        from nova_arsenal.context.compression import ContentCompressor

        comp = ContentCompressor()
        security_content = """
        Nmap scan results for 10.0.0.1
        PORT     STATE SERVICE VERSION
        22/tcp   open  ssh     OpenSSH 7.6p1
        80/tcp   open  http    Apache/2.4.29
        443/tcp  open  https   Apache/2.4.29
        CVE-2021-41773 detected in Apache 2.4.49
        Severity: CRITICAL
        """
        result = comp.compress(
            content=security_content,
            query_keywords=["CVE", "vulnerable", "port", "critical"],
        )
        assert isinstance(result, str)

    def test_segment_content(self):
        from nova_arsenal.context.compression import ContentCompressor

        comp = ContentCompressor()
        content = "line1\nline2\nline3\n" * 100
        segments = comp.segment_content(content, max_segment_size=200)
        assert len(segments) > 1
        for seg in segments:
            assert len(seg) > 0

    def test_score_segments_by_keywords(self):
        from nova_arsenal.context.compression import ContentCompressor

        comp = ContentCompressor()
        segments = [
            "CVE-2021-41773 critical vulnerability",
            "normal text here",
            "port 80 open http",
        ]
        scored = comp.score_segments_by_keywords(segments, ["CVE", "critical"])
        assert len(scored) == 3
        # CVE segment should score highest
        assert scored[0][1] > scored[1][1]

"""Tests for CTF Solver module."""

import pytest
from nova_arsenal.ctf_solver import CtfSolver, ChallengeType, CtfFlag, CtfChallenge


class TestCtfSolver:
    def test_initialization(self):
        solver = CtfSolver()
        assert solver.challenges == []
        assert solver.solved_challenges == []
        assert solver.total_points == 0
        assert solver.solved_points == 0

    def test_classify_web(self):
        solver = CtfSolver()
        ctype = solver.classify_challenge("Web Exploitation", "SQL injection in login", "http://ctf.example.com")
        assert ctype == ChallengeType.WEB

    def test_classify_crypto(self):
        solver = CtfSolver()
        ctype = solver.classify_challenge("Crypto 100", "RSA encrypted message")
        assert ctype == ChallengeType.CRYPTO

    def test_classify_stego(self):
        solver = CtfSolver()
        ctype = solver.classify_challenge("Hidden Image", "Steganography challenge")
        assert ctype == ChallengeType.STEGO

    def test_classify_osint(self):
        solver = CtfSolver()
        ctype = solver.classify_challenge("Find the Person", "OSINT recon search")
        assert ctype == ChallengeType.OSINT

    def test_classify_pwn(self):
        solver = CtfSolver()
        ctype = solver.classify_challenge("Buffer Overflow", "pwn binary exploit")
        assert ctype == ChallengeType.PWN

    def test_classify_default_misc(self):
        solver = CtfSolver()
        ctype = solver.classify_challenge("random challenge", "some description")
        assert ctype == ChallengeType.MISC

    def test_extract_flags_standard(self):
        solver = CtfSolver()
        flags = solver.extract_flags("The flag is flag{hello_world}")
        assert len(flags) >= 1
        assert flags[0].flag in ("hello_world", "flag{hello_world}")

    def test_extract_flags_ctf_format(self):
        solver = CtfSolver()
        flags = solver.extract_flags("CTF{supersecret}")
        assert len(flags) >= 1

    def test_extract_flags_multiple(self):
        solver = CtfSolver()
        flags = solver.extract_flags("flag{first} and CTF{second}")
        assert len(flags) >= 2

    def test_extract_flags_confidence_high(self):
        solver = CtfSolver()
        flags = solver.extract_flags("flag{real_flag}")
        assert flags[0].confidence == 1.0

    def test_add_challenge(self):
        solver = CtfSolver()
        c = solver.add_challenge("test-challenge", "web challenge", ChallengeType.WEB, points=100)
        assert c.name == "test-challenge"
        assert c.challenge_type == ChallengeType.WEB
        assert c.points == 100
        assert len(solver.challenges) == 1
        assert solver.total_points == 100

    def test_add_challenge_auto_classify(self):
        solver = CtfSolver()
        c = solver.add_challenge("SQL Injection Lab", points=50)
        assert c.challenge_type == ChallengeType.WEB

    def test_get_stats_empty(self):
        solver = CtfSolver()
        stats = solver.get_stats()
        assert stats["total_challenges"] == 0
        assert stats["solved"] == 0
        assert stats["completion_pct"] == 0.0

    def test_get_stats_with_solved(self):
        solver = CtfSolver()
        solver.add_challenge("c1", challenge_type=ChallengeType.WEB, points=100)
        solver.add_challenge("c2", challenge_type=ChallengeType.CRYPTO, points=200)
        c = solver.challenges[0]
        c.solved = True
        c.flag = CtfFlag(flag="flag{ok}", challenge_type=ChallengeType.WEB)
        solver.solved_challenges.append(c)
        solver.solved_points = 100

        stats = solver.get_stats()
        assert stats["total_challenges"] == 2
        assert stats["solved"] == 1
        assert stats["solved_points"] == 100
        assert stats["total_points"] == 300
        assert stats["completion_pct"] == 50.0

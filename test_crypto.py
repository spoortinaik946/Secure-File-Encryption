import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from app import encrypt_bytes, decrypt_bytes

def test_encrypt_decrypt_round_trip():
    original = b"Information Network and Security mini project"
    encrypted = encrypt_bytes(original, "CorrectHorseBattery9")
    assert encrypted != original
    assert decrypt_bytes(encrypted, "CorrectHorseBattery9") == original

def test_wrong_password_is_rejected():
    encrypted = encrypt_bytes(b"confidential data", "CorrectHorseBattery9")
    with pytest.raises(ValueError):
        decrypt_bytes(encrypted, "WrongPassword123")

def test_tampered_data_is_rejected():
    encrypted = bytearray(encrypt_bytes(b"important data", "CorrectHorseBattery9"))
    encrypted[-1] ^= 1
    with pytest.raises(ValueError):
        decrypt_bytes(bytes(encrypted), "CorrectHorseBattery9")

def test_invalid_format_is_rejected():
    with pytest.raises(ValueError):
        decrypt_bytes(b"not an encrypted file", "CorrectHorseBattery9")
#!/usr/bin/env python3
"""
Veriduct Prime - Example Usage

This script demonstrates the core capabilities of Veriduct Prime.
"""

import os
import sys
import tempfile
import hashlib

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from veriduct_prime import (
    annihilate_path,
    reassemble_path,
    run_annihilated_path,
    calculate_file_hash,
    semantic_shatter,
    semantic_unshatter,
    entangle_chunks,
    disentangle_chunks,
)


def example_basic_annihilation():
    """Basic annihilation and reassembly."""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Annihilation and Reassembly")
    print("="*60)
    
    # Create a test file
    test_content = b"Hello, Veriduct! " * 1000  # ~17KB
    
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
        f.write(test_content)
        test_file = f.name
    
    print(f"Created test file: {test_file}")
    print(f"Original size: {len(test_content)} bytes")
    print(f"Original hash: {hashlib.sha256(test_content).hexdigest()[:16]}...")
    
    # Create output directories
    chunks_dir = tempfile.mkdtemp()
    rebuilt_dir = tempfile.mkdtemp()
    
    # Annihilate
    print("\nAnnihilating...")
    result = annihilate_path(
        input_path=test_file,
        out_dir=chunks_dir,
        verbose=False
    )
    
    if result == 0:
        print(f"✓ Annihilation complete")
        print(f"  Chunks: {chunks_dir}/veriduct_chunks.db")
        print(f"  Keymap: {chunks_dir}/veriduct_key.zst")
    
    # Reassemble
    print("\nReassembling...")
    result = reassemble_path(
        key_path=os.path.join(chunks_dir, "veriduct_key.zst"),
        out_dir=rebuilt_dir,
        verbose=False
    )
    
    if result == 0:
        rebuilt_file = os.path.join(rebuilt_dir, os.path.basename(test_file))
        with open(rebuilt_file, 'rb') as f:
            rebuilt_content = f.read()
        
        rebuilt_hash = hashlib.sha256(rebuilt_content).hexdigest()[:16]
        print(f"✓ Reassembly complete")
        print(f"  Rebuilt size: {len(rebuilt_content)} bytes")
        print(f"  Rebuilt hash: {rebuilt_hash}...")
        
        if rebuilt_content == test_content:
            print(f"✓ VERIFIED: Byte-perfect reconstruction!")
    
    # Cleanup
    os.unlink(test_file)


def example_ssm():
    """Demonstrate Semantic Shatter Mapping."""
    print("\n" + "="*60)
    print("EXAMPLE 2: Semantic Shatter Mapping (SSM)")
    print("="*60)
    
    original = b"ABCDEFGHIJKLMNOP"
    print(f"Original: {original}")
    
    # Shatter
    shattered, seed, null_positions = semantic_shatter(original, null_insert_rate=0.0)
    print(f"Shattered: {shattered}")
    print(f"Seed: {seed.hex()[:16]}...")
    
    # Unshatter
    restored = semantic_unshatter(shattered, seed, null_positions)
    print(f"Restored: {restored}")
    
    if restored == original:
        print(f"✓ SSM reversal verified!")


def example_entanglement():
    """Demonstrate XOR entanglement."""
    print("\n" + "="*60)
    print("EXAMPLE 3: XOR Entanglement")
    print("="*60)
    
    chunks = [
        b"AAAA",
        b"BBBB",
        b"CCCC",
    ]
    
    print("Original chunks:")
    for i, c in enumerate(chunks):
        print(f"  C{i}: {c}")
    
    # Entangle
    entangled, info = entangle_chunks(chunks, group_size=3)
    
    print("\nEntangled chunks:")
    for i, e in enumerate(entangled):
        print(f"  E{i}: {e}")
    
    # Disentangle
    restored = disentangle_chunks(entangled, info)
    
    print("\nRestored chunks:")
    for i, r in enumerate(restored):
        print(f"  R{i}: {r}")
    
    if all(r == c for r, c in zip(restored, chunks)):
        print(f"✓ Entanglement reversal verified!")


def example_full_pipeline():
    """Full pipeline with all features."""
    print("\n" + "="*60)
    print("EXAMPLE 4: Full Pipeline (SSM + Entanglement + Poisoning)")
    print("="*60)
    
    # Create a test file
    test_content = b"X" * 10000 + b"Y" * 10000  # 20KB
    
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
        f.write(test_content)
        test_file = f.name
    
    original_hash = hashlib.sha256(test_content).hexdigest()
    print(f"Original hash: {original_hash[:32]}...")
    
    chunks_dir = tempfile.mkdtemp()
    rebuilt_dir = tempfile.mkdtemp()
    
    # Annihilate with all features
    print("\nAnnihilating with SSM + Entanglement + Fake Chunks...")
    result = annihilate_path(
        input_path=test_file,
        out_dir=chunks_dir,
        use_ssm=True,
        use_entanglement=True,
        use_fake_chunks=True,
        fake_ratio=0.3,
        verbose=False
    )
    
    if result == 0:
        print(f"✓ Annihilation complete with all features")
    
    # Reassemble
    print("\nReassembling...")
    result = reassemble_path(
        key_path=os.path.join(chunks_dir, "veriduct_key.zst"),
        out_dir=rebuilt_dir,
        verbose=False
    )
    
    if result == 0:
        rebuilt_file = os.path.join(rebuilt_dir, os.path.basename(test_file))
        with open(rebuilt_file, 'rb') as f:
            rebuilt_hash = hashlib.sha256(f.read()).hexdigest()
        
        print(f"Rebuilt hash:  {rebuilt_hash[:32]}...")
        
        if original_hash == rebuilt_hash:
            print(f"✓ VERIFIED: Perfect reconstruction with all features!")
    
    # Cleanup
    os.unlink(test_file)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("VERIDUCT PRIME - EXAMPLES")
    print("="*60)
    
    example_basic_annihilation()
    example_ssm()
    example_entanglement()
    example_full_pipeline()
    
    print("\n" + "="*60)
    print("ALL EXAMPLES COMPLETE")
    print("="*60)

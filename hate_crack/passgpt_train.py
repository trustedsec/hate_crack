"""Fine-tune a PassGPT model on a custom password wordlist.

Invokable as ``python -m hate_crack.passgpt_train``.  Progress and
diagnostic messages go to stderr.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys


# Disable HuggingFace telemetry before any HF imports
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"


def _detect_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def _configure_mps() -> None:
    """Set MPS memory limits before torch is imported."""
    os.environ.setdefault("PYTORCH_MPS_HIGH_WATERMARK_RATIO", "0.5")
    os.environ.setdefault("PYTORCH_MPS_LOW_WATERMARK_RATIO", "0.3")


def _get_available_memory_mb() -> int | None:
    """Return available system RAM in MB, or None if detection fails."""
    try:
        if sys.platform == "linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) // 1024
            return None
        elif sys.platform == "darwin":
            # macOS: try os.sysconf first, fall back to sysctl
            try:
                page_size = os.sysconf("SC_PAGE_SIZE")
                avail_pages = os.sysconf("SC_AVPHYS_PAGES")
                if page_size > 0 and avail_pages > 0:
                    return (page_size * avail_pages) // (1024 * 1024)
            except (ValueError, OSError):
                pass
            # Fallback: use sysctl for total memory (not available, but better than nothing)
            try:
                result = subprocess.run(
                    ["sysctl", "-n", "hw.memsize"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return int(result.stdout.strip()) // (1024 * 1024)
            except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
                pass
            return None
        else:
            return None
    except Exception:
        return None


def _count_lines(filepath: str) -> int:
    """Count non-empty lines in a file without loading it into memory."""
    count = 0
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def _estimate_training_memory_mb(
    training_file: str, max_length: int = 16, max_lines: int = 0
) -> int:
    """Estimate peak memory usage in MB for training on the given file.

    Components:
    - Model: ~500MB (GPT-2 small)
    - Optimizer states: ~1000MB (2x model for AdamW momentum/variance)
    - Dataset offset index: ~8 bytes per line
    - Per-batch activations and tokenization buffer: ~200MB
    """
    num_lines = _count_lines(training_file)
    if max_lines > 0:
        num_lines = min(num_lines, max_lines)

    model_mb = 500
    optimizer_mb = 1000
    # Offset index: 8 bytes per line (Python int in list)
    index_mb = (num_lines * 8) // (1024 * 1024)
    # Activation/buffer overhead
    buffer_mb = 200

    return model_mb + optimizer_mb + index_mb + buffer_mb


def train(
    training_file: str,
    output_dir: str,
    base_model: str,
    epochs: int,
    batch_size: int,
    device: str | None,
    max_lines: int = 0,
    memory_limit: int = 0,
) -> None:
    # --- Memory pre-check ---
    if memory_limit > 0:
        # Auto-tune max_lines to fit within memory_limit
        estimated_base = _estimate_training_memory_mb(training_file, max_lines=1)
        per_line_bytes = 8  # offset index cost per line
        available_for_data = (memory_limit - estimated_base) * 1024 * 1024
        if available_for_data > 0:
            auto_max_lines = available_for_data // per_line_bytes
            if max_lines == 0 or auto_max_lines < max_lines:
                max_lines = max(1, int(auto_max_lines))
                print(
                    f"[*] --memory-limit {memory_limit}MB: auto-set --max-lines to {max_lines}",
                    file=sys.stderr,
                )
        else:
            print(
                f"[!] --memory-limit {memory_limit}MB is too low for model overhead alone.",
                file=sys.stderr,
            )
            sys.exit(1)

    estimated = _estimate_training_memory_mb(training_file, max_lines=max_lines)
    available = _get_available_memory_mb()
    if available is not None and estimated > available:
        print(
            f"[!] Estimated memory usage ({estimated}MB) exceeds available RAM ({available}MB).",
            file=sys.stderr,
        )
        print(
            "[!] Use --max-lines to limit wordlist size or --memory-limit to auto-tune.",
            file=sys.stderr,
        )
        sys.exit(1)

    if device == "mps" or device is None:
        _configure_mps()

    import torch
    from transformers import (  # type: ignore[attr-defined]
        GPT2LMHeadModel,
        RobertaTokenizerFast,
        Trainer,
        TrainingArguments,
    )

    if device is None:
        device = _detect_device()

    print(f"[*] Loading base model {base_model} on {device}", file=sys.stderr)
    tokenizer = RobertaTokenizerFast.from_pretrained(base_model)
    model = GPT2LMHeadModel.from_pretrained(base_model).to(device)  # type: ignore[arg-type]

    max_length = (
        model.config.n_positions if hasattr(model.config, "n_positions") else 16
    )

    # Enable gradient checkpointing to reduce activation memory
    model.gradient_checkpointing_enable()

    print(f"[*] Indexing training file: {training_file}", file=sys.stderr)

    class LazyPasswordDataset(torch.utils.data.Dataset):  # type: ignore[type-arg]
        """Dataset that indexes file byte offsets and tokenizes on-the-fly."""

        def __init__(
            self,
            filepath: str,
            tokenizer: object,
            max_length: int,
            max_lines: int = 0,
        ):
            self.filepath = filepath
            self.tokenizer = tokenizer
            self.max_length = max_length
            self.offsets: list[int] = []
            with open(filepath, "rb") as f:
                while True:
                    offset = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if line.strip():
                        self.offsets.append(offset)
                        if max_lines > 0 and len(self.offsets) >= max_lines:
                            break

        def __len__(self) -> int:
            return len(self.offsets)

        def __getitem__(self, idx: int) -> dict[str, object]:
            with open(self.filepath, "rb") as f:
                f.seek(self.offsets[idx])
                line = f.readline().decode("utf-8", errors="replace").strip()
            enc = self.tokenizer(  # type: ignore[operator]
                line,
                truncation=True,
                padding="max_length",
                max_length=self.max_length,
                return_tensors="pt",
            )
            input_ids = enc["input_ids"].squeeze(0)
            attention_mask = enc["attention_mask"].squeeze(0)
            return {
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "labels": input_ids,
            }

    dataset = LazyPasswordDataset(training_file, tokenizer, max_length, max_lines)
    print(f"[*] Indexed {len(dataset)} passwords", file=sys.stderr)

    # Use CPU for training args if device is MPS (Trainer handles device placement)
    use_cpu = device not in ("cuda",)
    use_fp16 = device == "cuda"
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        save_strategy="epoch",
        logging_steps=100,
        use_cpu=use_cpu,
        report_to="none",
        push_to_hub=False,
        gradient_accumulation_steps=4,
        fp16=use_fp16,
        gradient_checkpointing=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
    )

    print(
        f"[*] Starting training: {epochs} epochs, batch_size={batch_size}, device={device}",
        file=sys.stderr,
    )
    trainer.train()

    print(f"[*] Saving model to {output_dir}", file=sys.stderr)
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print("[*] Training complete.", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fine-tune a PassGPT model on a password wordlist"
    )
    parser.add_argument(
        "--training-file",
        type=str,
        required=True,
        help="Path to the password wordlist for training",
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="javirandor/passgpt-10characters",
        help="Base HuggingFace model to fine-tune (default: javirandor/passgpt-10characters)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="Directory to save the fine-tuned model",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs (default: 3)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="Training batch size (default: 8)",
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Device: cuda, mps, or cpu (default: auto-detect)",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=0,
        help="Limit training to the first N lines of the wordlist (default: 0, no limit)",
    )
    parser.add_argument(
        "--memory-limit",
        type=int,
        default=0,
        help="Memory cap in MB; auto-tunes --max-lines to fit (default: 0, no limit)",
    )
    args = parser.parse_args()
    train(
        training_file=args.training_file,
        output_dir=args.output_dir,
        base_model=args.base_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        device=args.device,
        max_lines=args.max_lines,
        memory_limit=args.memory_limit,
    )


if __name__ == "__main__":
    main()

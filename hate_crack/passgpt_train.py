"""Fine-tune a PassGPT model on a custom password wordlist.

Invokable as ``python -m hate_crack.passgpt_train``.  Progress and
diagnostic messages go to stderr.
"""

from __future__ import annotations

import argparse
import os
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


def train(
    training_file: str,
    output_dir: str,
    base_model: str,
    epochs: int,
    batch_size: int,
    device: str | None,
) -> None:
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

    print(f"[*] Reading training file: {training_file}", file=sys.stderr)
    with open(training_file, encoding="utf-8", errors="replace") as f:
        passwords = [line.strip() for line in f if line.strip()]
    print(f"[*] Loaded {len(passwords)} passwords", file=sys.stderr)

    print("[*] Tokenizing passwords...", file=sys.stderr)
    max_length = model.config.n_positions if hasattr(model.config, "n_positions") else 16
    encodings = tokenizer(
        passwords,
        truncation=True,
        padding="max_length",
        max_length=max_length,
        return_tensors="pt",
    )

    class PasswordDataset(torch.utils.data.Dataset):  # type: ignore[type-arg]
        def __init__(self, encodings):
            self.input_ids = encodings["input_ids"]
            self.attention_mask = encodings["attention_mask"]

        def __len__(self):
            return len(self.input_ids)

        def __getitem__(self, idx):
            return {
                "input_ids": self.input_ids[idx],
                "attention_mask": self.attention_mask[idx],
                "labels": self.input_ids[idx],
            }

    dataset = PasswordDataset(encodings)

    # Use CPU for training args if device is MPS (Trainer handles device placement)
    use_cpu = device not in ("cuda",)
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        save_strategy="epoch",
        logging_steps=100,
        use_cpu=use_cpu,
        report_to="none",
        push_to_hub=False,
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
    args = parser.parse_args()
    train(
        training_file=args.training_file,
        output_dir=args.output_dir,
        base_model=args.base_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        device=args.device,
    )


if __name__ == "__main__":
    main()

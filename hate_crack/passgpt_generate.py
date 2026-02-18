"""Standalone PassGPT password candidate generator.

Invokable as ``python -m hate_crack.passgpt_generate``.  Outputs one
candidate password per line to stdout so it can be piped directly into
hashcat.  Progress and diagnostic messages go to stderr.
"""

from __future__ import annotations

import argparse
import sys


def _detect_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def generate(
    num: int,
    model_name: str,
    batch_size: int,
    max_length: int,
    device: str | None,
) -> None:
    import torch
    from transformers import GPT2LMHeadModel, RobertaTokenizerFast

    if device is None:
        device = _detect_device()

    print(f"[*] Loading model {model_name} on {device}", file=sys.stderr)
    tokenizer = RobertaTokenizerFast.from_pretrained(model_name)
    model = GPT2LMHeadModel.from_pretrained(model_name).to(device)
    model.eval()

    generated = 0
    seen: set[str] = set()

    print(f"[*] Generating {num} candidates (batch_size={batch_size})", file=sys.stderr)
    with torch.no_grad():
        while generated < num:
            current_batch = min(batch_size, num - generated)
            input_ids = torch.full(
                (current_batch, 1),
                tokenizer.bos_token_id,
                dtype=torch.long,
                device=device,
            )
            output = model.generate(
                input_ids,
                max_length=max_length,
                do_sample=True,
                top_k=0,
                top_p=1.0,
                num_return_sequences=current_batch,
                pad_token_id=tokenizer.eos_token_id,
            )
            # Strip BOS token
            output = output[:, 1:]
            for seq in output:
                decoded = tokenizer.decode(seq, skip_special_tokens=False)
                password = decoded.split("</s>")[0]
                if password and password not in seen:
                    seen.add(password)
                    sys.stdout.write(password + "\n")
                    generated += 1
                    if generated >= num:
                        break

    sys.stdout.flush()
    print(f"[*] Done. Generated {generated} unique candidates.", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate password candidates using PassGPT"
    )
    parser.add_argument(
        "--num",
        type=int,
        default=1000000,
        help="Number of candidates to generate (default: 1000000)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="javirandor/passgpt-10characters",
        help="HuggingFace model name (default: javirandor/passgpt-10characters)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1024,
        help="Generation batch size (default: 1024)",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=12,
        help="Max token length including special tokens (default: 12)",
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Device: cuda, mps, or cpu (default: auto-detect)",
    )
    args = parser.parse_args()
    generate(
        num=args.num,
        model_name=args.model,
        batch_size=args.batch_size,
        max_length=args.max_length,
        device=args.device,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Benchmark multiple Ollama models for password candidate generation.

Runs the same prompt against each model and compares response time,
throughput, candidate count, and refusal behavior.

Usage:
    python tools/ollama_benchmark.py                          # defaults
    python tools/ollama_benchmark.py mistral phi3             # specific models
    python tools/ollama_benchmark.py --prompt "custom prompt"
    python tools/ollama_benchmark.py --output results.json
    python tools/ollama_benchmark.py --num-ctx 2048 8192 32768  # compare context sizes
"""

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request

DEFAULT_MODELS = ["llama3.2", "mistral", "phi3", "gemma2", "qwen2.5"]

DEFAULT_PROMPT = (
    "Generate baseword to be used in a denylist for keeping users from "
    "setting their passwords with these basewords. We are protecting the "
    "employees of Acme Corp in the technology industry located in Austin, TX.\n\n"
    "Include variations with:\n"
    "- Company name variations and abbreviations\n"
    "- Common password patterns (Season+Year, Name+Numbers)\n"
    "- Keyboard walks and common substitutions (@ for a, 3 for e, etc.)\n"
    "- Location-based words and local references\n"
    "- Industry-specific terminology\n"
    "Output ONLY the passwords, one per line, no numbering or explanation."
)

DEFAULT_NUM_CTX = [2048, 8192, 32768]
TIMEOUT = 600


def pull_model(url, model):
    """Pull an Ollama model. Returns True on success, False on failure."""
    print(f"  Model '{model}' not found locally. Pulling...")
    pull_url = f"{url}/api/pull"
    payload = json.dumps({"name": model, "stream": True}).encode("utf-8")
    req = urllib.request.Request(
        pull_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                status = data.get("status")
                if status:
                    print(f"    {status}")
    except (urllib.error.HTTPError, urllib.error.URLError, Exception) as e:
        print(f"  Error pulling model: {e}")
        return False
    print(f"  Successfully pulled '{model}'.")
    return True


def filter_candidates(response_text):
    """Filter raw LLM response into usable password candidates."""
    raw_lines = response_text.strip().split("\n")
    candidates = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            continue
        cleaned = re.sub(r"^\d+[.)]\s*", "", stripped)
        cleaned = re.sub(r"^[-*]\s*", "", cleaned)
        cleaned = cleaned.strip()
        if cleaned and len(cleaned) <= 128:
            candidates.append(cleaned)
    return candidates


def benchmark_model(url, model, prompt, num_ctx):
    """Run the prompt against a single model at a given context size. Returns a results dict."""
    api_url = f"{url}/api/generate"
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_ctx": num_ctx},
    }).encode("utf-8")

    result = {
        "model": model,
        "num_ctx": num_ctx,
        "response_time_s": None,
        "tokens_per_sec": None,
        "candidate_count": 0,
        "unique_candidates": 0,
        "refusal": False,
        "error": None,
    }

    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            if not pull_model(url, model):
                result["error"] = f"could not pull model"
                return result
            # Retry after pull
            req = urllib.request.Request(
                api_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            start = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
            except Exception as retry_err:
                result["error"] = str(retry_err)
                return result
        else:
            result["error"] = f"HTTP {e.code}"
            return result
    except (urllib.error.URLError, Exception) as e:
        result["error"] = str(e)
        return result

    elapsed = time.monotonic() - start
    result["response_time_s"] = round(elapsed, 2)

    # Extract tokens/sec from Ollama response metadata
    eval_count = body.get("eval_count")
    eval_duration = body.get("eval_duration")  # nanoseconds
    if eval_count and eval_duration and eval_duration > 0:
        result["tokens_per_sec"] = round(eval_count / (eval_duration / 1e9), 2)

    response_text = body.get("response", "")

    # Refusal detection
    if "I'm sorry" in response_text or "I can't help with that" in response_text:
        result["refusal"] = True

    candidates = filter_candidates(response_text)
    result["candidate_count"] = len(candidates)
    result["unique_candidates"] = len(set(candidates))
    result["candidates"] = candidates
    result["response"] = response_text

    return result


def print_table(results):
    """Print a formatted comparison table."""
    headers = ["Model", "num_ctx", "Time (s)", "Tok/s", "Candidates", "Unique", "Refusal", "Error"]
    rows = []
    for r in results:
        rows.append([
            r["model"],
            str(r["num_ctx"]),
            str(r["response_time_s"] or "-"),
            str(r["tokens_per_sec"] or "-"),
            str(r["candidate_count"]),
            str(r["unique_candidates"]),
            "YES" if r["refusal"] else "no",
            r["error"] or "",
        ])

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    def fmt_row(cells):
        return "  ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(cells))

    print()
    print(fmt_row(headers))
    print("  ".join("-" * w for w in col_widths))
    for row in rows:
        print(fmt_row(row))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark Ollama models for password candidate generation",
    )
    parser.add_argument(
        "models",
        nargs="*",
        default=DEFAULT_MODELS,
        help=f"Models to benchmark (default: {' '.join(DEFAULT_MODELS)})",
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="Override the generation prompt",
    )
    parser.add_argument(
        "--num-ctx",
        nargs="+",
        type=int,
        default=DEFAULT_NUM_CTX,
        metavar="N",
        help=f"Context window sizes to test (default: {' '.join(str(n) for n in DEFAULT_NUM_CTX)})",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write raw results to a JSON file",
    )
    args = parser.parse_args()

    url = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    if not url.startswith("http"):
        url = f"http://{url}"

    print(f"Ollama endpoint: {url}")
    print(f"Models: {', '.join(args.models)}")
    print(f"num_ctx values: {', '.join(str(n) for n in args.num_ctx)}")
    print()

    results = []
    for model in args.models:
        for num_ctx in args.num_ctx:
            print(f"Benchmarking {model} (num_ctx={num_ctx})...")
            r = benchmark_model(url, model, args.prompt, num_ctx)
            if r["error"]:
                print(f"  Error: {r['error']}")
            else:
                print(f"  {r['response_time_s']}s, {r['tokens_per_sec']} tok/s, "
                      f"{r['candidate_count']} candidates ({r['unique_candidates']} unique)"
                      f"{', REFUSED' if r['refusal'] else ''}")
            results.append(r)

    print_table(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results written to {args.output}")


if __name__ == "__main__":
    main()

import logging
import os
from typing import Optional


def resolve_path(value: Optional[str]) -> Optional[str]:
    """Expand user and return an absolute path, or None."""
    if not value:
        return None
    return os.path.abspath(os.path.expanduser(value))


def apply_config_overrides(args, config):
    """Apply CLI config overrides to the provided config object."""
    if args.hashview_url:
        config.hashview_url = args.hashview_url
    if args.hashview_api_key is not None:
        config.hashview_api_key = args.hashview_api_key
    if args.hcat_path:
        config.hcatPath = resolve_path(args.hcat_path)
    if args.hcat_bin:
        config.hcatBin = args.hcat_bin
    if args.wordlists_dir:
        config.hcatWordlists = resolve_path(args.wordlists_dir)
    if args.optimized_wordlists_dir:
        config.hcatOptimizedWordlists = resolve_path(args.optimized_wordlists_dir)
    if args.pipal_path:
        config.pipalPath = resolve_path(args.pipal_path)
    if args.maxruntime is not None:
        config.maxruntime = args.maxruntime
    if args.bandrel_basewords:
        config.bandrelbasewords = args.bandrel_basewords


def add_common_args(parser) -> None:
    parser.add_argument('--hashview-url', dest='hashview_url', help='Override Hashview URL')
    parser.add_argument('--hashview-api-key', dest='hashview_api_key', help='Override Hashview API key')
    parser.add_argument('--hcat-path', dest='hcat_path', help='Override hashcat path')
    parser.add_argument('--hcat-bin', dest='hcat_bin', help='Override hashcat binary name')
    parser.add_argument('--wordlists-dir', dest='wordlists_dir', help='Override wordlists directory')
    parser.add_argument('--optimized-wordlists-dir', dest='optimized_wordlists_dir', help='Override optimized wordlists directory')
    parser.add_argument('--pipal-path', dest='pipal_path', help='Override pipal path')
    parser.add_argument('--maxruntime', type=int, help='Override max runtime setting')
    parser.add_argument('--bandrel-basewords', dest='bandrel_basewords', help='Override bandrel basewords setting')


def setup_logging(logger: logging.Logger, hate_path: str, debug_mode: bool) -> None:
    if not debug_mode:
        return
    logger.setLevel(logging.DEBUG)
    if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
        log_path = os.path.join(hate_path, "hate_crack.log")
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(file_handler)

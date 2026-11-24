"""Command-line interface for SentinelX."""
import argparse
import json
from .analyzer import analyze_file, write_report

def main():
    parser = argparse.ArgumentParser(
        description="SentinelX: defensive authentication-log threat detector"
    )
    parser.add_argument("logfile", help="Path to a supported authentication log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed logins from one IP needed for an alert (default: 5)")
    parser.add_argument("--output", default="sentinelx-report.json",
                        help="JSON report output path")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    result = analyze_file(args.logfile, threshold=args.threshold)
    write_report(result, args.output)
    print(json.dumps(result, indent=2))
    print(f"\nReport saved to: {args.output}")

if __name__ == "__main__":
    main()

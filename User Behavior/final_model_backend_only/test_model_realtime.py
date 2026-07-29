import argparse
from xdr_runtime import run_inference


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Realtime user behavior anomaly scoring.")
    parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=120,
        help="Only use events in the last N minutes (default: 120). Use 0 for all history.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Optional anomaly threshold override (otherwise uses model_threshold.json).",
    )
    parser.add_argument(
        "--usb-override-threshold",
        type=int,
        default=10,
        help="If device_events >= this value in lookback window, force ANOMALY (default: 10). Use 0 to disable.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print("=" * 80)
    print("REAL-TIME USER BEHAVIOR TESTING")
    print("=" * 80)

    results = run_inference(
        lookback_minutes=args.lookback_minutes,
        threshold_override=args.threshold,
        usb_override_threshold=args.usb_override_threshold,
    )
    print("\n[1/5] Loading model artifacts...")
    print("   [OK] Model loaded")
    print("   [OK] Scaler features loaded")
    print(f"   [OK] Threshold: {results['threshold']:.2f}")
    print("\n[2/5] Parsing Windows logs...")
    print(f"   [OK] Found {results['log_files_count']} log files")
    print(f"   [OK] Parsed {results['events_count']} events (lookback={results['lookback_minutes']} minutes)")
    print("\n[3/5] Extracting features from logs...")
    print(f"   [OK] Found {results['summary']['total_users']} unique users")
    print(f"   [OK] Extracted features for {results['summary']['total_users']} users")
    print("\n[4/5] Preparing features for model...")
    print("   [OK] Features scaled")
    print("\n[5/5] Making predictions...")
    print("   [OK] Predictions complete")

    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    total = results["summary"]["total_users"]
    anomalies = results["summary"]["anomaly"]
    normal = results["summary"]["normal"]
    print("\nSUMMARY:")
    print(f"   Total users analyzed: {total}")
    print(f"   Normal behavior: {normal} ({(normal / total) * 100:.1f}%)")
    print(f"   Anomalous behavior: {anomalies} ({(anomalies / total) * 100:.1f}%)")

    print("\nANOMALIES DETECTED:\n")
    anomaly_rows = [r for r in results["rows"] if r["prediction_label"] == "ANOMALY"]
    if not anomaly_rows:
        print("No anomalies in this sample.")
    else:
        print("user prediction_label anomaly_score total_logins usb_connects")
        for row in anomaly_rows:
            print(
                f"{row['user']} {row['prediction_label']} {row['anomaly_score']} "
                f"{row['total_logins']} {row['usb_connects']}"
            )

    print("\nTESTING COMPLETE!")


if __name__ == "__main__":
    main()

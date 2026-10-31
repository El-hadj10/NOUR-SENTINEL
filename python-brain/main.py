
import json
import sys

from analyzer import analyze_events


def main():
    try:
        data = json.load(sys.stdin)

        result = analyze_events(data)

        # stdout is reserved exclusively for JSON.
        json.dump(result, sys.stdout, indent=4)
        sys.stdout.write("\n")
        sys.stdout.flush()

    except Exception as error:
        print(
            f"[PYTHON ERROR] {error}",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

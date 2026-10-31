
import json
import sys

from analyzer import analyze_events


def main():
    try:
        data = json.load(sys.stdin)

        result = analyze_events(data)

        json.dump(result, sys.stdout, indent=4)
        sys.stdout.write("\n")

    except Exception as error:
        print(
            f"Python analysis error: {error}",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

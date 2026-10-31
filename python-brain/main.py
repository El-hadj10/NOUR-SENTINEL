
import json
import sys

from analyzer import analyze_events


def main():
    try:
        raw_data = sys.stdin.read()
        data = json.loads(raw_data)

        result = analyze_events(data)

        print(json.dumps(result, indent=4))

    except json.JSONDecodeError:
        print(
            json.dumps({
                "status": "error",
                "message": "Invalid JSON input"
            }),
            file=sys.stdout
        )
        sys.exit(1)

    except Exception as error:
        print(
            json.dumps({
                "status": "error",
                "message": str(error)
            }),
            file=sys.stdout
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

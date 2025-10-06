import sys

def parse_cavs_file(path):
    with open (path, 'r') as f:
        test_cases = []
        current = {}

        for line in f:
            line = line.strip()

            if not line or line.startswith('#') or line.startswith('['):
                continue

            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == 'Len':
                    current['Len'] = int(value)
                elif key == 'Msg':
                    current['Msg'] = value
                elif key == 'MD':
                    current['MD'] = value
                    test_cases.append(current)
                    current = {}
    return test_cases

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python cavs_parser.py <filename>")
        sys.exit(1)

    path = sys.argv[1]
    vectors = parse_cavs_file(path)

    print(f"Parsed {len(vectors)} test cases from {path}:")
    for v in vectors[:3]:
        print(v)
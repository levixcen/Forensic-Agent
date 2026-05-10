import sys
from Evtx.Evtx import Evtx


def convert_evtx_to_txt(evtx_path, output_path):
    results = []
    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                results.append(record.xml())
            except Exception:
                continue

    with open(output_path, 'w', encoding='utf-8') as f:
        # Each record on its own line so the smart_filter block-splitter works cleanly
        f.write('\n'.join(results))

    print(f"Converted {len(results)} records to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_evtx.py input.evtx output.txt")
        sys.exit(1)

    convert_evtx_to_txt(sys.argv[1], sys.argv[2])
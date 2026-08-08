# Member 3 – Symmetric Cryptography Experiment

Complete implementation and benchmarking code for the project **Performance
and Security Evaluation of Symmetric Cryptographic Algorithms: DES, 3DES, and
AES**.

## What this package contains

- `crypto_algorithms.py`: DES-CBC, 3DES-CBC and AES-128-CBC encryption/decryption.
- `test_algorithms.py`: correctness, UTF-8, empty/large message, random-IV and wrong-key tests.
- `benchmark.py`: repeated encryption/decryption measurements and CSV export.
- `results/`: generated raw measurements and machine/environment information.

PyCryptodome provides the cryptographic implementations. The project code
handles key generation, CBC mode, random IVs, PKCS#7 padding, correctness
testing, timing and data collection.

> DES and 3DES are included only for academic comparison. They must not be used
> to protect new real-world systems. AES-GCM is normally preferable for modern
> authenticated encryption.

## Setup in PyCharm

1. Open this folder as a PyCharm project.
2. Select a Python 3.10+ virtual environment.
3. Open PyCharm Terminal and run:

```bash
python -m pip install -r requirements.txt
```

## Verify correctness

```bash
python -m unittest -v test_algorithms.py
```

All three tests should finish with `OK`.

## Run a quick benchmark

Use this first to confirm the program works:

```bash
python benchmark.py --runs 3 --warmups 1 --sizes 1024 10240
```

## Run the final experiment

```bash
python benchmark.py
```

The default experiment measures 1 KB, 10 KB, 100 KB, 1 MiB and 5 MiB. Each
case has 3 warm-ups and 30 measured runs. Outputs:

- `results/performance_raw.csv`
- `results/environment.txt`

The CSV contains one raw row per run and operation. Throughput is calculated as:

```text
throughput (MiB/s) = data size (MiB) / elapsed time (seconds)
```

Run the final experiment on one machine, close heavy background applications,
and do not combine results collected on different computers.

## Suggested handoff

- Member 1: use the raw results for the performance discussion.
- Member 2: cite PyCryptodome, CBC, padding, keys and IV handling in methodology.
- Member 4: aggregate the CSV by algorithm, size and operation; calculate mean,
  median and standard deviation; then create charts.

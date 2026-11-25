# Vhost-fuzzer
Python script for fuzzing vhost with the SNI header in the TLS handshke.


PS C:\tmp> python3 .\vhost-fuzz-sni.1.0.py --help
usage: vhost-fuzz-sni.1.0.py [-h] [-t TARGET] [-T TARGET_FILE] [-p PORT] -w WORDLIST [--path PATH] [--method METHOD]
                             [-H RAW_HEADERS] [--user-agent USER_AGENT] [--threads THREADS] [--timeout TIMEOUT]
                             [--delay DELAY] [--retries RETRIES] [--max-body MAX_BODY] [--filter-code FILTER_CODE]
                             [--filter-size FILTER_SIZE] [--filter-baseline] [--show-all] [--no-baseline] [--no-cert]
                             [--cert-only] [--proxy PROXY] [--debug] [-o OUTPUT] [--unique-out UNIQUE_OUT] [--jsonl JSONL]
                             [--output-body]

VHOST fuzzer — TLS SNI matches Host header on every request

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target IP or hostname
  -T, --target-file TARGET_FILE
                        File of target IPs/hostnames
  -p, --port PORT       Target port (default 443)
  -w, --wordlist WORDLIST
                        VHOST wordlist (one per line)
  --path PATH           Request path (default /)
  --method METHOD       HTTP method (default GET; HEAD is faster)
  -H, --header RAW_HEADERS
                        Extra request header, repeatable ('X-Foo: bar')
  --user-agent USER_AGENT
                        Override User-Agent
  --threads THREADS     Concurrent threads (default 10)
  --timeout TIMEOUT     Timeout seconds (default 8)
  --delay DELAY         Per-request delay in seconds, jittered 0.5-1.5x (default 0)
  --retries RETRIES     Retries on transient errors (default 0)
  --max-body MAX_BODY   Max response body bytes to read (default 512KB)
  --filter-code FILTER_CODE
                        Comma-separated status codes to hide
  --filter-size FILTER_SIZE
                        Hide responses with this exact body size
  --filter-baseline     Hide anything whose fingerprint matches the IP's baseline
  --show-all            Show errored probes too
  --no-baseline         Skip baseline probe
  --no-cert             Skip certificate parsing (faster)
  --cert-only           TLS handshake only, no HTTP request — fast cert/SAN harvest
  --proxy PROXY         Proxy URL (http://[user:pass@]host:port)
  --debug               Print SNI values sent
  -o, --output OUTPUT   Write raw results to CSV
  --unique-out UNIQUE_OUT
                        Write deduped results to a second CSV
  --jsonl JSONL         Write results as JSON Lines
  --output-body         Include response body in CSV

Only use against systems you own or are authorised to test.

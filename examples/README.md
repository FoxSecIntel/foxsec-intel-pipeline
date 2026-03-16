# Examples

Batch input file:

- `domains.txt`: one domain per line

Generate outputs:

```bash
python3 foxsec_scan.py --input-file examples/domains.txt --output json > examples/output.json
python3 foxsec_scan.py --input-file examples/domains.txt --output csv > examples/output.csv
python3 foxsec_scan.py --input-file examples/domains.txt --output markdown > examples/output.md
python3 foxsec_scan.py --input-file examples/domains.txt --output html > examples/output.html
```

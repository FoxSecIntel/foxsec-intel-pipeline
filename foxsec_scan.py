#!/usr/bin/env python3
import sys
if len(sys.argv) > 1 and sys.argv[1] in ("-a", "--author"):
    print("Author: FoxSecIntel")
    print("Repository: https://github.com/FoxSecIntel/foxsec-intel-pipeline
    print("Tool: foxsec_scan.py")
    raise SystemExit(0)


from main import main


if __name__ == "__main__":
    raise SystemExit(main())

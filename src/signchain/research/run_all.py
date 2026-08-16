"""
Convenience entry point to run full research benchmarking suite.
"""
from signchain.research.run_experiments import main

if __name__ == "__main__":
    import sys
    sys.argv = ["run_all.py", "--run-all"]
    main()

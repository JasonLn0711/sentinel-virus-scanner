CARGO ?= cargo

.PHONY: product-check test demo rust-fmt rust-test rust-lint rust-prepare-eicar rust-verify rust-demo rust-evidence clean

product-check: rust-verify rust-evidence

test: rust-test

demo: rust-demo

rust-fmt:
	cd rust && $(CARGO) fmt --check

rust-test:
	cd rust && $(CARGO) test

rust-lint:
	cd rust && $(CARGO) clippy --all-targets -- -D warnings

rust-prepare-eicar:
	cd rust && $(CARGO) run -- prepare-eicar-demo --target ../demo/demo-tree

rust-verify: rust-fmt rust-test rust-lint rust-prepare-eicar
	cd rust && $(CARGO) run -- verify-demo --target ../demo/demo-tree --signatures ../signatures/malware-signatures.json

rust-demo: rust-prepare-eicar
	cd rust && $(CARGO) run -- scan --target ../demo/demo-tree --signatures ../signatures/malware-signatures.json --json ../reports/demo-report.json --markdown ../reports/demo-report.md; status=$$?; if [ $$status -ne 1 ]; then exit $$status; fi

rust-evidence: rust-demo
	cd rust && $(CARGO) run -- write-evidence --target ../demo/demo-tree --signatures ../signatures/malware-signatures.json --report ../reports/demo-report.json --report ../reports/demo-report.md --output ../reports/demo-evidence-manifest.json

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf dist build rust/target

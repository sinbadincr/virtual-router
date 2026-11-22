# Thin wrapper over CMake and the lab scripts.
PRESET ?= debug
.PHONY: build test test-asan check lab lab-run lab-clean e2e e2e-kvm clean

build:
	cmake --preset $(PRESET) && cmake --build --preset $(PRESET) -j

test: build
	ctest --preset $(PRESET)
	@if [ -x scripts/check-fastpath.sh ]; then scripts/check-fastpath.sh; fi

test-asan:
	cmake --preset asan && cmake --build --preset asan -j && ctest --preset asan

check:
	scripts/check.sh

# the lab: KVM guests behind the forwarder (needs /dev/kvm). TOPO=overlay: two compute nodes,
# an emulated underlay and 5 guests (specs/003-vrf-overlay-tunnels).
TOPO ?= single
lab:
	lab/lab.sh up --topo $(TOPO)

lab-run:
	lab/lab.sh run

lab-clean:
	lab/lab.sh down

# the harness suite: namespace VMs, crafted frames, no KVM needed
e2e:
	tests/e2e/run.sh

# the KVM suite: the same lab as `make lab`
e2e-kvm:
	tests/e2e/run.sh --kvm

clean:
	rm -rf build

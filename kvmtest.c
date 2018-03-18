#include <err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/kvm.h>

int main(int argc, char **argv)
{
	int kvmfd, vmfd, vcpufd;
	int rc;
	void *mem;
	size_t mmap_sz;
	struct kvm_run *run;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_userspace_memory_region region;
	const uint8_t code[] = {
		0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
		0x00, 0xd8,       /* add %bl, %al */
		0x04, '0',        /* add $'0', %al */
		0xee,             /* out %al, (%dx) */
		0xb0, '\n',       /* mov $'\n', %al */
		0xee,             /* out %al, (%dx) */
		0xf4,             /* hlt */
	};

	kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvmfd < 0) {
		err(1, "cannot open /dev/kvm");
	}
	rc = ioctl(kvmfd, KVM_GET_API_VERSION, NULL);
	if (rc == -1) {
		err(1, "api version");
	}
	if (rc != 12) {
		errx(1, "api version %d, expected 12", rc);
	}
	rc = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	if (rc == -1) {
		err(1, "extension");
	}
	if (!rc) {
		errx(1, "required extension KVM_CAP_USER_MEMORY not available");
	}
	vmfd = ioctl(kvmfd, KVM_CREATE_VM, (unsigned long)0);
	if (vmfd < 0) {
		err(1, "create vm");
	}
	mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		err(1, "mmap");
	}
	memcpy(mem, code, sizeof(code));
	region = (struct kvm_userspace_memory_region){
		.slot = 0,
		.guest_phys_addr = 0x1000,
		.memory_size = 0x1000,
		.userspace_addr = (uint64_t)mem,
	};
	rc = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (rc < 0) {
		err(1, "region");
	}
	vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
	if (vcpufd < 0) {
		err(1, "create vcpu");
	}
	mmap_sz = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	run = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
	if (run == MAP_FAILED) {
		err(1, "mmap run");
	}
	ioctl(vcpufd, KVM_GET_SREGS, &sregs);
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ioctl(vcpufd, KVM_SET_SREGS, &sregs);
	regs = (struct kvm_regs){
		.rip = 0x1000,
		.rax = 2,
		.rbx = 2,
		.rflags = 0x2,
	};
	ioctl(vcpufd, KVM_SET_REGS, &regs);
	while (1) {
		ioctl(vcpufd, KVM_RUN, NULL);
		switch(run->exit_reason) {
			case KVM_EXIT_HLT:
				puts("hlt");
				return 0;
			case KVM_EXIT_IO:
				if (run->io.direction == KVM_EXIT_IO_OUT &&
						run->io.size == 1 &&
						run->io.port == 0x3f8 &&
						run->io.count == 1) {
					putchar(*(((char *)run + run->io.data_offset)));
				}
				else {
					errx(1, "unhandled io exit");
				}
				break;
			case KVM_EXIT_FAIL_ENTRY:
				errx(1, "fail entry: hw reason=0x%llx",
						(unsigned long long)run->fail_entry.hardware_entry_failure_reason);
				break;
			case KVM_EXIT_INTERNAL_ERROR:
				errx(1, "internal error: suberror=0x%x",
						run->internal.suberror);
				break;
		}
	}

	return 0;
}

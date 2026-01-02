include Makefile.vars

# Sources and outputs
SRCS := $(wildcard *.bpf.c)
OBJS := $(SRCS:%.bpf.c=$(OUT_DIR)/%.bpf.o)
DEPS := $(OBJS:.bpf.o=.d)

.PHONY: all
all: libbpf $(OBJS)

# just including vmlinux.h in everything, run this if you need to regenerate it
.PHONY: kernel_headers
kernel_headers:
ifeq ($(BTF_SUPPORTED),1)
	@echo "$(GREEN)Kernel BTF information found$(NC)"
	$(Q)bpftool btf dump file $(KRBTF) format c > $(VMLINUX)/vmlinux.h
else
	@echo "$(RED)Kernel BTF information not found$(NC)"
endif

.PHONY: libbpf
libbpf: $(LIBBPF)/src/libbpf.a

$(LIBBPF)/src/libbpf.a:
#	@git submodule update --init --recursive
	@$(MAKE) -C $(LIBBPF)/src

# Compile eBPF programs

# generate .d files for header dependencies
$(OUT_DIR)/%.d: %.bpf.c
	$(Q)$(CL) $(KF) -MF -MMD -MP -Xclang -disable-llvm-passes -c $< -o /dev/null

$(OUT_DIR)/%.bpf.o: %.bpf.c $(VMLINUX_H) $(OUT_DIR)/%.d
	@echo "Compiling eBPF bytecode: $(GREEN)$@$(NC) ..."
	$(Q)$(CL) $(KF) -Xclang -disable-llvm-passes -c $< -o - \
	  | opt -O2 -mtriple=bpf-pc-linux \
	  | llvm-dis \
	  | llc -march=bpf -mcpu=probe -filetype=obj -o $@

# Include generated dependency files to recompile when .h files change
-include $(DEPS)

.PHONY: clean
clean:
	$(Q)rm -rf *.o $(OUT_DIR)/*.d $(VMLINUX)/vmlinux.h

.PHONY: clean-all
clean-all: clean
	$(Q)make clean -C $(LIBBPF)/src

file(REMOVE_RECURSE
  "../qemu/config-host.mak"
  "../qemu/riscv64-softmmu/qemu-system-riscv64"
  "CMakeFiles/qemu"
  "qemu-secure-boot.patch.applied"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/qemu.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()

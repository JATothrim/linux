/*
 * Common module linker script, always used when linking a module.
 * Archs are free to supply their own linker scripts.  ld will
 * combine them automatically.
 */
#ifdef CONFIG_CFI_CLANG
# include <asm/page.h>
# define ALIGN_CFI 		ALIGN(PAGE_SIZE)
# define SANITIZER_DISCARDS	*(.eh_frame)
#else
# define ALIGN_CFI
# define SANITIZER_DISCARDS
#endif

SECTIONS {
	/DISCARD/ : {
		*(.discard)
		*(.discard.*)
		SANITIZER_DISCARDS
	}

	__ksymtab		0 : { *(SORT(___ksymtab+*)) }
	__ksymtab_gpl		0 : { *(SORT(___ksymtab_gpl+*)) }
	__kcrctab		0 : { *(SORT(___kcrctab+*)) }
	__kcrctab_gpl		0 : { *(SORT(___kcrctab_gpl+*)) }

	.ctors			0 : ALIGN(8) { *(SORT(.ctors.*)) *(.ctors) }
	.init_array		0 : ALIGN(8) { *(SORT(.init_array.*)) *(.init_array) }

	__jump_table		0 : ALIGN(8) { KEEP(*(__jump_table)) }

	__patchable_function_entries : { *(__patchable_function_entries) }

#ifdef CONFIG_LTO_CLANG
	/*
	 * With CONFIG_LTO_CLANG, LLD always enables -fdata-sections and
	 * -ffunction-sections, which increases the size of the final module.
	 * Merge the split sections in the final binary.
	 */
	.bss : {
		*(.bss .bss.[0-9a-zA-Z_]*)
		*(.bss..L*)
	}

	.data : {
		*(.data .data.[0-9a-zA-Z_]*)
		*(.data..L*)
	}

	.rodata : {
		*(.rodata .rodata.[0-9a-zA-Z_]*)
		*(.rodata..L*)
	}

	/*
	 * With CONFIG_CFI_CLANG, we assume __cfi_check is at the beginning
	 * of the .text section, and is aligned to PAGE_SIZE.
	 */
	.text : ALIGN_CFI {
		*(.text.__cfi_check)
		*(.text .text.[0-9a-zA-Z_]* .text..L.cfi*)
	}
#endif
#ifdef CONFIG_PGO_CLANG
	/*
	 * With CONFIG_PGO_CLANG the compiler may split __llvm_prf_xxx
	 * objects into multiple sections. Merge them in final .ko object.
	 * However leave .rela__llvm_prf_data sections as-is
	 * since they are needed by the module loader.
	 */
	__llvm_prf_data : AT(ADDR(__llvm_prf_data)) {
		__llvm_prf_data_start = .;
		KEEP(*(SORT(__llvm_prf_data)))
		__llvm_prf_data_end = .;
	}
	__llvm_prf_cnts : AT(ADDR(__llvm_prf_cnts)) {
		__llvm_prf_cnts_start = .;
		KEEP(*(SORT(__llvm_prf_cnts)))
		__llvm_prf_cnts_end = .;
	}
	__llvm_prf_names : AT(ADDR(__llvm_prf_names)) {
		__llvm_prf_names_start = .;
		KEEP(*(SORT(__llvm_prf_names)))
		__llvm_prf_names_end = .;
	}
	__llvm_prf_vals : AT(ADDR(__llvm_prf_vals)) {
		__llvm_prf_vals_start = .;
		KEEP(*(SORT(__llvm_prf_vals)))
		__llvm_prf_vals_end = .;
	}
	__llvm_prf_vnds : AT(ADDR(__llvm_prf_vnds)) {
		__llvm_prf_vnds_start = .;
		KEEP(*(SORT(__llvm_prf_vnds)))
		__llvm_prf_vnds_end = .;
	}
#endif
}

/* bring in arch-specific sections */
#include <asm/module.lds.h>

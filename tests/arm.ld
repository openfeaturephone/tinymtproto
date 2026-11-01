/* arm_check.py: a position-independent image with no writable data, the same shape as an app
 * for a loader that copies one blob into RAM and jumps to it. */
ENTRY(tmt_entry)
SECTIONS
{
    . = 0;
    .text : {
        *(.text .text.*)
        *(.rodata .rodata.*)
        . = ALIGN(8);
    }
    /* -fropi has no RW relocation support: writable data must not exist */
    .data : { *(.data .data.* .bss .bss.* COMMON) }
    ASSERT(SIZEOF(.data) == 0, "the library must not have writable data")
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}

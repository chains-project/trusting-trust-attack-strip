ENTRY(parasite_entry)

SECTIONS
{
    . = 0;
    __parasite_start = .;

    .text : {
        *(.text.entry)
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    .rodata.patch : {
        *(.rodata.patch)
    }

    __parasite_end = .;

    /DISCARD/ : {
        *(.note*)
        *(.eh_frame*)
        *(.comment*)
        *(.gnu.build*)
        *(.gnu.hash*)
        *(.dynamic)
        *(.dynstr*)
        *(.dynsym*)
        *(.gnu.version*)
        *(.rela*)
        *(.rel*)
        *(.got*)
        *(.plt*)
        *(.bss*)
        *(.data)
    }
}
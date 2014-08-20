/*
 * Linker script to build a boot record
 */
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
ENTRY(_start)

SECTIONS
{
    . = 0x7c00;
    .boottext : { *(.boottext) }
    .bootdata : { *(.bootdata) }

    . = 0x7dfe;
    .bootmagic : {
        BYTE(0x55);
        BYTE(0xaa);
    }
}

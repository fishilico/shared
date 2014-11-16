/*
 * Display a white-on-blue message using BIOS interrupts
 *
 * To run in Qemu, use one of these commands:
 * * qemu-system-i386 -hda blue_message.bin
 * * qemu-system-i386 -fda blue_message.bin -boot a
 */
	.code16
	.section ".boottext", "ax"
	. = 0
	.globl	_start
_start:
	/* First, disable interrupts */
	cli

	/* Ensure we started at 0000:7C00 and not 07C0:0000 */
	ljmp	$0, $start2
start2:
	/* Reset segment registers */
	xorw	%ax, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	/* Set stack as right before the code */
	movw	$0x7c00, %sp
	sti
	cld

	/* Set video mode to mode 0x12:
	 * * text resolution 80x30
	 * * pixel resolution 640x480
	 * * colors 16/256K
	 * * VGA
	 */
	movw	$0x0012, %ax
	int	$0x10

	/* Set blue background color */
	movw	$0x0b00, %ax
	movw	$0x0001, %bx
	int	$0x10

	/* Set cursor position of page 0 to (row 14, col 31) */
	movb	$0x02, %ah
	xorb	%bh, %bh
	movw	$0x0e1f, %dx
	int	$0x10

	/* Get cursor position in %dx */
	movb	$0x03, %ah
	xorb	%bh, %bh
	int	$0x10

	/* Print string */
	movw	$0x1301, %ax
	movw	$0x000f, %bx /* page 0, color white */
	movw	message_len, %cx
	movw	$message, %bp
	int	$0x10

wait_key:
	xorw	%ax, %ax
	int	$0x16

reboot:
	int	$0x19
	/* invoke the BIOS reset code if int 0x19 returned */
	ljmp	$0xf000,$0xfff0

hang:
	cli
1:
	hlt
	jmp	1b

	.section ".bootdata", "a"
message:
	.ascii	"The world is blue!\r\n\nPress a key to continue...\n"
	/* Hack to make the string displays correctly on QEmu with Seabios,
	 * where "cx=65" displays 78 characters */
	.space (65 - (. - message)), '\r'
message_len = (. - message)
	.space (78 - message_len), '\r'

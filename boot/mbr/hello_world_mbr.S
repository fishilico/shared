/*
 * Display "Hello, world!" using BIOS interrupts
 *
 * To run in Qemu, use one of these commands:
 * * qemu-system-i386 -hda hello_world_mbr.bin
 * * qemu-system-i386 -fda hello_world_mbr.bin -boot a
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

	movw	$message, %si

print_message:
	lods	%ds:(%si), %al
	andb	%al, %al
	jz	wait_key
	movb	$0xe, %ah
	movw	$7, %bx
	/* Print character in teletype mode */
	int	$0x10
	jmp	print_message

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
	.ascii	"Hello, world!\r\n"

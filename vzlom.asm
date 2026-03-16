.model tiny
.code
org 100h
locals @@

; start just calls main
; it is needed so we can use @@ labels 
; inside the Main proc
Start:  call Main
        ; std dos interrupt func with 4c00h exits the program
        mov ax, 4c00h ; DIIIIE
        int 21h

; ----------------------------------------VZLOM ZHOPI----------------------------------------------
; this program will ask you to type in the password, which is
; hard coded in the code below. 
; If hash of password you type matches
;         the hash of password stated in the code,
;         program prints 'Access Granted'
; if not  it      prints 'Access Denied'
; there are two vulnerabilities, coded specially for the opponent to hack
;   1)  buffer can overflow easily, as there are no checks to prevent it
;       so you can fill the password buffer with garbage and then rewrite function 
;       below it(replace je command with jne). Coincedentally, that exact function is responsible
;       for checking if you have correctly or incorrectly guessed the password
;       and prints corresponding string
;   2)  you can type in more than 15 symbols when program asks you to guess password
;       when buffer will overflow and next byte is Status code. If status code is 1 - accsess granted
;       if 0 - access denied. You can type 15 of any symbols and then 01h hex symbol, this will overwrite StatusPassed var
;       and cause program to misbehave
; -------------------------------------------------------------------------------------------------
Main proc
        ; prints string which asks user
        ; to type their password
        mov dx, offset AskUserPassword
        call PrintString

        ; we will be using dos standart interrupt function(code is 21h)
        ; but with argument 08h in ah.
        ; 01 argument waits for an argument in the command line from the user
        ; and then places it in the al regex(with no echo)
        mov ah, 08h

        xor di, di ; di is our len of str
        @@LoopGetPass:
            ; call 08h dos interrupt func
            ; al will be ascii code of pressed key
            int 21h

            ; if pressed key is enter
            ; then leave the program
            cmp al, 0dh
            je @@LoopExit

            ; if pressed key is backspace
            ; then 'remove' one char from our buffer
            ; 'remove' means that we decrement char counter by 1
            ; and fill the previously typed char to '$'
            cmp al, 08h
            jne @@SkipDelChar

            dec di
            mov Buffer[di], '$'
            jmp @@LoopGetPass

            @@SkipDelChar:

            ; moving to the buffer pressed key
            ; so buffer contains users password
            ; and then incrementing our len(di)
            mov Buffer[di], al
            inc di
            jmp @@LoopGetPass
        @@LoopExit:

        ; si = address of str we want to calculate hash for
        mov si, offset Buffer
        call GetHashInCx

        ; now in cx we have have of 
        ; users password
        ; in PasswordHash var is hash of required passwords
        ; we are comparing those passwords
        ; and if they are equal, in bx is placed 1(Correct Guess)
        ; else in bx is 0(Incorrect Guess)
        cmp cx, PasswordHash
        jne @@SkipBxInc

        inc StatusPassed
        
        @@SkipBxInc:

        ; print if we gain access or if it is denied
        call CheckAndGiveAccess

        ret
endp

; =================================Melody segment==================================
A       equ 2714d
B       equ 2416d
D       equ 2031d
E       equ 1809d
F       equ 1611d
C       equ 2152d

MelodyLose:
    dw A,   1 
    dw B,   1  
    dw D,   1  
    dw B,   1  
    dw F,   1    
    dw 0,   2
    dw F,   1       
    dw 0,   2
    dw E,   4      

    dw 0,   3

    dw A,   1
    dw B,   1
    dw D,   1 
    dw B,   1 
    dw E,   1    
    dw 0,   2
    dw E,   1       
    dw 0,   2
    dw D,   4 
    dw C,   1  
    dw B,   2     

    dw 0,   0 

MelodyWin:
    dw 2232, 2   
    dw 1910, 2
    dw 1556, 2   
    dw 2032, 2   
    dw 1710, 2
    dw 1356, 2 
    dw 1810, 2
    dw 1522, 2
    dw 1209, 2   
    dw 1139, 4   
    dw 0, 0 
; ==============================End of Melody segment==============================

; ==================================DATA SEGMENT==================================
; strings when we ask user to type password, and
; when we print whether we gain access or deny it
AskUserPassword     db 'Please type your password: $'
CorrectPassword     db 'Access Granted$'
IncorrectPassword   db 'Access denied$'

; hard coded password
PasswordHash        dw 0456h

; buffer which can overflow 
; it is supposed to contain the password,
; which user typed in console
Buffer              db 15 dup('$')
StatusPassed        dw 00h
; ==============================END OF DATA SEGMENT================================

;----------------------------------------------
; prints whether users password was a correct guess or no
; EXP:		StatusPassed = 1 if password is correct, 0 if incorrect
; OUT:		prints string to the console
; Destroys:	dx, ax
;----------------------------------------------
CheckAndGiveAccess proc
    ; if bx = 0(incorrect) when print IncorrectPassword string
    ; else print CorrectPassword string
    cmp StatusPassed, 00h
    je @@Incorrect

    mov dx, offset CorrectPassword
	call PrintString

    mov dx, offset MelodyWin
    call PlayMelody
    ret

    @@Incorrect:
    mov dx, offset IncorrectPassword
	call PrintString

    mov dx, offset MelodyLose
    call PlayMelody
    ret
endp

PlayMelody proc
    mov si, dx
    @@PlayMelodyLoop:
        mov ax, [si]
        cmp ax, 0
        jne @@PlayNote

            ; here we will wait and not play a note
            cmp word ptr [si + 2], 0h
            je @@ExitPlayMelodyLoop

            call WaitWhilePlaying
            add si, 4h
            jmp @@PlayMelodyLoop

        @@PlayNote:

        call TurnOnPlayer
        call WaitWhilePlaying
        call TurnOffPlayer

        add si, 4h
        jmp @@PlayMelodyLoop
    @@ExitPlayMelodyLoop:
    ret
endp

TurnOnPlayer proc
    push ax
    mov al, 0b6h
    out 43h, al
    pop ax

    out 42h, al
    mov al, ah
    out 42h, al

    in  al, 61h
    or  al, 00000011b
    out 61h, al

    ret
endp

WaitWhilePlaying proc
    mov cx, 0001h
    mov dx, 0e848h
    mov ax, [si + 2]     ; Number of bits to shift (e.g., 5)
    test ax, ax
    je @@SkipWaiting

    @@ShiftLoop:
        dec ax
        jz @@ExitShiftLoop

        add dx, 0e848h
        adc cx, 0001h

        jmp @@ShiftLoop
    @@ExitShiftLoop:
    mov ah, 86h
    int 15h
    @@SkipWaiting:
    ret
endp

TurnOffPlayer proc
    in al, 61h
    and al, 11111100b
    out 61h, al

    ret
endp  

; -------------------------------------------------
; prints string located in dx to the console
; IN:       dx - address of the str
; OUT:      prints str to the console
; EXP:      dx is ended by '$' symbol
; DESTR:    AX
; -------------------------------------------------
PrintString proc
    ; in dx is the address of the string we chose to print.
    ; when we call 09h dos interrupt func, which
    ; takes string address in dx, ending in '$' and prints
    ; it to the console
    mov ah, 09h
    int 21h
    ret
endp

; -------------------------------------------------
; returns hash of ds:[si] string to the cx regex
; IN:       ds:[si] - str
; OUT:      cx - hash of str
; DESTR:    CX, SI, BX
; -------------------------------------------------
GetHashInCx proc
    ; cx = 0 - future hash of our str
    xor cx, cx
    xor dx, dx

    @@Loop:
        ; if bx is 0 it means we scanned
        ; every char in str
        ; and we can exit the Loop
        cmp byte ptr ds:[si], '$'
        je @@ExitLoop
        ; adds to cl ascii code of char in str
        mov dl, ds:[si]
        add cx, dx
        ; when move on to the next char
        inc si

        ; else just repeat the process
        ; with the next char
        jmp @@Loop
    @@ExitLoop:
    ret
endp

end             Start
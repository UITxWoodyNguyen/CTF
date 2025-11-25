# Ready Gladiator 

### Information
* Category: RE
* Point:
* Level: Medium

### Description
Can you make a CoreWars warrior that wins every single round? Your opponent is the Imp. The source is available here. If you wanted to pit the Imp against himself, you could download the Imp and connect to the CoreWars server like this: 
```
nc saturn.picoctf.net <port> < imp.red 
```
To get the flag, you must beat the Imp all `N` rounds.

## Part 1
Min of `N` is 2 (at lease once).
### Hint
You may be able to find a viable warrior in beginner docs

### Solution
#### What we got ?
- We got a `.red` file. However, it just has the classic minimal imp `(mov 0,1)`, which is really hard to win.
```red
;redcode 
;name Imp Ex 
;assert 1 

mov 0, 1 
end
```
- Explanation why: `mov 0, 1` copies the current instruction into the next memory cell and then the process continues — that produces an imp, a self-moving instruction that walks around core. Imps are simple and sometimes survive, but they rarely win against smarter opponents (they can be too slow, or get outmaneuvered).
- Method to win more often:

    1. Imp: extremely simple, very robust vs. some opponents, but rarely tournament-winner alone.
    2. Dwarf / Bomber: repeatedly drop DAT bombs at intervals; good vs. slower code.
    3. Replicator (paper): reproduce itself and overwrite opponents; more complex but powerful.
    4. Scanner + Coe: probe memory, then attack found patterns (advanced).

#### How to get the flag ?
- Try using the (2) method (Dwarf / Bomber). To make it simple, we will writes `DAT` into core at a moving target pointer. Tune the `step` constant to change spacing.

```red
;redcode
;name Imp Ex
;assert 1

start   mov  #bomb, @target    ; write DAT at target
        add  #step, target     ; move target forward
        jmp  -2                ; loop back to start

target  dat  0, 0              ; pointer cell (will be used as target)
bomb    dat  0, 0              ; the actual bomb we copy
step    dat  5, 0              ; spacing between bombs (tweak this)

end
```
- Connect to the server to play and get the flag:

    ![Flag]()

---
## Part 2
### Hint


### Solution
#### What we got ?


#### How to get the flag ?

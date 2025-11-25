# Core Wars for Dummies  
*By J.K. Lewis*

## Introduction  
- **What is Core War?**  
  A programming game in which two or more “warrior” programs (written in an assembly-type language called Redcode) battle in a simulated computer memory called a “core”. :contentReference[oaicite:3]{index=3}  
- The objective: your warrior tries to destroy the enemy warrior(s) by causing them to execute illegal instructions or otherwise eliminating their processes, so that yours remains.  
- It’s a fun way to learn low-level programming concepts (addresses, instructions, loops) but in a competitive format.

## Basics of the Game  
- The simulated machine is called a **MARS** (Memory Array Redcode Simulator) — each instruction occupies a memory cell. :contentReference[oaicite:4]{index=4}  
- Warriors are loaded into memory, each gets one or more processes (threads of execution) that execute instructions one at a time in cycles.  
- On each cycle, each active process executes an instruction; if all processes of a warrior die (e.g., due to illegal instruction, being overwritten, etc), the warrior loses.

## Redcode Language Overview  
- Instructions are assembly-style: e.g., `MOV`, `ADD`, `SUB`, `JMP`, `DAT`, etc.  
- Addressing modes: immediate, direct, indirect, etc. These determine how operands are interpreted.  
- A simple example warrior might use `DAT` (data/instruction) to create traps, or `JMP`/`SPL` to create multiple processes (“splitting”) for parallel execution.  
- The tutorial emphasizes writing small but effective programs, understanding offsets, relative addressing, and how to survive in the core battlefield.

## Strategies & Tactics  
- **Dwarf**: A small warrior that executes quickly and repeatedly attacks by overwriting opponents at fixed offsets.  
- **Scanner**: A warrior that searches memory for enemy code (by looking for non‐zero instructions or signatures) and then attacks.  
- **Vampire**: A warrior that uses the `SPL` instruction to “steal” processes from the enemy.  
- The tutorial encourages experimenting: try simple strategies, see how they fail, then refine them.

## Practical Tips for Beginners  
- Start with very simple warriors (e.g., “imp” loops) and observe how they behave.  
- Use a simulator (such as pMARS) so you can step through execution, watch processes, memory changes. :contentReference[oaicite:6]{index=6}  
- Understand how the core memory wraps around (addresses increment modulo the core size).  
- Comments and readability matter — even though programs are small, understanding what your code does helps for tuning.  
- Keep in mind the performance trade-offs: fast (few cycles) vs. robust (handles different opponents).  
- Study other warriors’ code: reading and understanding simple working examples is a good way to learn.

## Summary & Next Steps  
- The game teaches low-level programming, memory management, concurrency (processes), and strategy — all in a compact, fun package.  
- After mastering the basics, you can move to more advanced topics: hills (ranking systems), tournament rules, advanced Redcode features.  
- Encouraged to join online communities, submit your warriors, test them against others, and iterate.

---

## Appendix (Key Terms)  
- **Core**: The simulated memory array where warriors execute.  
- **Process**: A thread or line of execution belonging to a warrior.  
- **DAT**: An instruction/data directive; often used to kill a process if executed.  
- **SPL**: “Split” — creates a new process, enabling parallelism.  
- **Scanner, Dwarf, Vampire**: Common warrior archetypes/strategies.  
- **Hill**: A ranking system for warriors; you submit your code and it competes over many rounds to be ranked.  


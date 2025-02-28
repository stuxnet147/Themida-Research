# Themida VM Analysis

## Table of Contents

1. [Overview](#overview)
2. [Themida VM Context Structure (`VM_CONTEXT`)](#themida-vm-context-structure-vm_context)
3. [Handler Operation Principles and Characteristics](#handler-operation-principles-and-characteristics)
4. [Handler Code Analysis Example](#handler-code-analysis-example)

---

## Overview

The Themida (or WinLicense family) obfuscation engine obfuscates binary code through a **virtual machine (VM)**. It particularly transforms x64 code into custom bytecode format, mixing various **virtual registers**, **virtual stack** operations, and **anti-debugging** techniques to provide a high level of complexity.

The key steps in reverse engineering are as follows:

1. **Understanding VM CONTEXT**
   - When executing the Themida VM, it backs up actual CPU registers/flags and internally operates VM-specific registers and stack.
2. **Handler Analysis**
   - Analysis of handlers that process each **virtualized instruction** (ADD, SUB, SHIFT, ROTATE, PUSH, POP, CALL, RET, ...).
3. **Bytecode Dispatch**
   - Using VM bytecode (or word-sized opcode) + handler table to dynamically calculate the next handler address.
4. **Implementing Lifting (Devirtualization)**
   - Semi-automatic/automatic restoration of **"bytecode → IR/original x86 code"** using Python + Triton, etc.

---

## Themida VM Context Structure (`VM_CONTEXT`)

Themida VM uses a VM CONTEXT of about **0x200 bytes**. The offsets of VM CONTEXT are randomly determined during the Themida obfuscation process.

```c
// This is a simplified example. Differs from actual implementation.
struct VM_CONTEXT
{
  char VM_CONTEXT_START;
  char field_1;
  char field_2;
  char field_3;
  char field_4;
  char field_5;
  char field_6;
  char field_7;
  char field_8;
  char field_9;
  char field_A;
  char field_B;
  char field_C;
  char field_D;
  __unaligned __declspec(align(1)) __int64 vm_opnd_maybe_1;
  __unaligned __declspec(align(1)) __int64 field_16;
  __unaligned __declspec(align(1)) int vm_some_key2;
  __unaligned __declspec(align(1)) __int64 vm_opaque_022;
  __unaligned __declspec(align(1)) int field_2A;
  __unaligned __declspec(align(1)) __int64 vReg_R11;
  __unaligned __declspec(align(1)) __int64 vm_opaque_036;
  __unaligned __declspec(align(1)) int vm_some_key1;
  char vm_unknown_flag;
  char field_43[12];
  char vm_branch_flag_maybe;
  __int64 vm_scratch_qword;
  int vm_some_key3;
  __unaligned __declspec(align(1)) __int64 field_5C;
  __unaligned __declspec(align(1)) __int64 vm_opnd_maybe_2;
  char vm_instruction_opcode5;
  __unaligned __declspec(align(1)) __int16 vm_opaque_06D;
  __unaligned __declspec(align(1)) __int64 vReg_R15;
  char vm_opaque_077[12];
  __unaligned __declspec(align(1)) __int64 vm_handlerScratch;
  __unaligned __declspec(align(1)) __int16 vm_opaque_08B;
  __unaligned __declspec(align(1)) __int64 vm_instruction_pointer;
  __unaligned __declspec(align(1)) int vm_some_key5;
  __unaligned __declspec(align(1)) __int64 vReg_R13;
  char vm_instruction_opcode2;
  __unaligned __declspec(align(1)) __int64 vm_some_key4;
  __unaligned __declspec(align(1)) __int64 vReg_RDI;
  __int16 field_B2;
  int vm_some_key7;
  char vm_instruction_opcode1;
  __unaligned __declspec(align(1)) __int16 vm_some_key6;
  __unaligned __declspec(align(1)) __int64 vReg_RBP;
  __unaligned __declspec(align(1)) __int64 vReg_RBX;
  __unaligned __declspec(align(1)) int pad;
  __unaligned __declspec(align(1)) __int64 vm_left_value_1;
  char vm_instruction_opcode4;
  int vm_opaque_0D8;
  __unaligned __declspec(align(1)) __int64 vReg_R9;
  __unaligned __declspec(align(1)) __int64 vReg_R10;
  __unaligned __declspec(align(1)) __int64 *vm_handlerTable;
  int vm_opaque_0F4;
  __int64 vReg_RCX;
  __int64 vm_opaque_100;
  int vm_handlerKey;
  __unaligned __declspec(align(1)) __int64 vReg_R8;
  __unaligned __declspec(align(1)) __int64 vReg_R14;
  __unaligned __declspec(align(1)) __int64 vm_opnd_maybe_3;
  __unaligned __declspec(align(1)) __int64 vReg_RAX;
  char vm_instruction_opcode3;
  char vm_opaque_12D[12];
  __unaligned __declspec(align(1)) __int64 vReg_R12;
  char vm_opaque_141[12];
  __unaligned __declspec(align(1)) __int64 vReg_RSI;
  char vm_operation_result_selector_maybe;
  __int16 vm_opaque_156;
  int vm_spinlock;
  __unaligned __declspec(align(1)) __int64 vm_stack_pointer;
  __unaligned __declspec(align(1)) __int64 vReg_RDX;
  __unaligned __declspec(align(1)) __int64 vm_left_value_2;
  char vm_opaque_174[140];
};
```

- **`vm_handlerTable`**: Used to fetch "handler" addresses from bytecode index (or opcode).
- **`vm_instruction_pointer`**: Pointer to the bytecode currently being interpreted?
- **`vm_stack_pointer`**: vsp

---

## Themida Operation Flow Overview

### VM ENTER:

Pushes the original context onto the stack

```
// Simplified example. Differs from actual implementation.
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
push rdi
push rsi
push rbp
push rbx
push rdx
push rcx
push rax
push eflags
push some_key
push first_handler_offset
push retaddr
...
```

Themida sets a spinlock before entry because all virtualized code shares a single global VM CONTEXT variable.

```
.themida:1400931D0 loc_1400931D0:
.themida:1400931D0  xor  eax, eax
.themida:1400931D2  lock cmpxchg [rbx+rbp], ecx ;rbx is spinlock offset and rbp is the start address of VM_CONTEXT
.themida:1400931D7  jz  loc_1400931E4
.themida:1400931DD  pause
.themida:1400931DF  jmp  loc_1400931D0
```

Moves context information pushed onto the stack to VM CONTEXT.

```
// Simplified example. Differs from actual implementation.
pop     qword ptr [r9]	;eflags to VM_CONTEXT
pop     qword ptr [r14]	;rax
pop     qword ptr [r14]	;rcx
pop     qword ptr [r15]	;rdx
pop     qword ptr [r15]	;rbx
pop     qword ptr [r15]	;rbp
pop     qword ptr [rsi]	;rsi
pop     qword ptr [rsi]	;rdi
pop     qword ptr [r12]	;r15
pop     qword ptr [r14]	;r14
pop     qword ptr [r14]	;r13
pop     qword ptr [r15]	;r12
pop     qword ptr [r15]	;r11
pop     qword ptr [r15]	;r10
pop     qword ptr [r15]	;r9
pop     qword ptr [r14]	;r8
...
```

### VM HANDLER:

In simple terms, this process interprets and executes bytecode. Note that Themida's bytecode is not a byte array.

Example handlers:

```
  // Simplified example. Differs from actual implementation.
  // mov operation
  if ( v0->vm_instruction_opcode1 == (char)0xEA )
  {
    v84 = v0->vm_opnd_maybe_1 + (v0->vm_some_key4 ^ v0->vm_opnd_maybe_2) - 0x6C1BFD75;
    v85 = v0->vm_left_value_1 + v0->vm_opnd_maybe_3 + 0x2787FB21 - v0->vm_some_key4;
    if ( v0->vm_instruction_opcode3 == 0x75 )
      v84 = (char)v85;
    if ( v0->vm_instruction_opcode3 == 0x76 )
      v84 = (__int16)(LOWORD(v0->vm_left_value_1) + LOWORD(v0->vm_opnd_maybe_3) - 0x4DF - LOWORD(v0->vm_some_key4));
    if ( v0->vm_instruction_opcode3 == 0x77 )
      v84 = (unsigned int)v85;
    v50 = v84 + v85;
    __readeflags();
    if ( v0->vm_operation_result_selector_maybe <= 0x8Eu )
      v0->vm_left_value_1 = v84 ^ 0x2787FB21;
    else
      v0->vm_left_value_2 = v84 + 0x116ABA2E;
  }
  
  // shr operation
  if ( v0->vm_instruction_opcode1 == 0x6D )
  {
    v214 = v0->vm_opnd_maybe_1 + (v0->vm_some_key4 ^ v0->vm_opnd_maybe_2) - 0x6C1BFD75;
    v215 = v0->vm_left_value_1 + v0->vm_opnd_maybe_3 + 0x2787FB21 - v0->vm_some_key4;
    v237 = *(_QWORD *)(&v0->VM_CONTEXT_START + *(unsigned __int16 *)(v0->vm_instruction_pointer + 0xB));
    if ( v0->vm_instruction_opcode2 == (char)0xA2 )
    {
      __writeeflags(v237);
      LOBYTE(v214) = (unsigned __int8)v214 >> v215;
      v216 = __readeflags();
      v237 = v216;
    }
    if ( v0->vm_instruction_opcode2 == (char)0xA3 )
    {
      __writeeflags(v237);
      LOWORD(v214) = (unsigned __int16)v214 >> v215;
      v217 = __readeflags();
      v237 = v217;
    }
    if ( v0->vm_instruction_opcode2 == (char)0xA4 )
    {
      __writeeflags(v237);
      v214 = (unsigned int)v214 >> v215;
      v218 = __readeflags();
      v237 = v218;
    }
    if ( v0->vm_instruction_opcode2 == (char)0xA5 )
    {
      __writeeflags(v237);
      v214 >>= v215;
      __readeflags();
    }
    vm_operation_result_selector_maybe = v0->vm_operation_result_selector_maybe;
    if ( vm_operation_result_selector_maybe <= 0x8Eu )
      v0->vm_left_value_1 = v214 ^ 0x2787FB21;
    else
      v0->vm_left_value_2 = v214 + 0x116ABA2E;
  }
```

Note that if it's an arithmetic operation, there is likely to be a pushfq (__readeflags) right after the operation.

```
  // Simplified example. Differs from actual implementation.
  // push operation
  if ( vm_instruction_opcode1 == 0x6A )
  {
    if ( (_BYTE)p_vm_instruction_opcode5 == 2 )
    {
      LOWORD(v34) = v18;
    }
    else
    {
      LOWORD(v34) = HIWORD(v18);
      v20 = ((_BYTE)v0 - 0x48) & (v18 + v20) ^ 0xF;
    }
  }
  
  ...
  
  // stack pointer adjust
  v26 = (p_vm_instruction_opcode5 | 0x47) - 4;
  v27 = v0->vm_instruction_opcode1 - 0x6A;
  if ( v0->vm_instruction_opcode1 == 0x6A )
  {
    if ( v24 == 2 )
    {
      *(_QWORD *)vm_stack_pointer -= 2LL;
    }
    else
    {
      *(_QWORD *)vm_stack_pointer -= 8LL;
      LOBYTE(v26) = v27 ^ (((v27 ^ v26) - 0xF) | 0x28);
    }
    v26 = (unsigned __int8)v26 & 0xA8;
  }
  LOBYTE(p_vm_instruction_opcode5) = v0->vm_instruction_opcode1;
  v28 = p_vm_instruction_opcode5 | (v26 + 0x8000FBFFLL);
  if ( (_BYTE)p_vm_instruction_opcode5 == 0x1C )
  {
    vm_opnd_maybe_1 = v0->vm_opnd_maybe_1;
    v28 = 0x400 - vm_opnd_maybe_1;
    if ( (char *)(vm_opnd_maybe_1 - 0x31AC9D7C) != vm_stack_pointer )
    {
      if ( v24 == 2 )
        *(_QWORD *)vm_stack_pointer += 2LL;
      else
        *(_QWORD *)vm_stack_pointer += 8LL;
      v28 = 0x3E4LL;
    }
  }
```

Themida doesn't go through a separate dispatcher in the handler. It moves directly from the handler to the next handler.

```
  // Simplified example. Differs from actual implementation.
  vmctx->vm_handlerKey -= 0x5AC92481;
  vmctx->vm_handlerKey ^= 0x3F8BFC4F;
  vmctx->vm_handlerKey ^= 0x2DDDE2;
  
  v1 = *(unsigned __int16 *)(vmctx->vm_instruction_pointer + 4);
  index = v1 - vmctx->vm_handlerKey;
  vmctx->vm_handlerKey &= index;
  
  next_handler = vmctx->vm_handlerTable[(unsigned __int16)index];
  
  // VIP update
  vmctx->vm_instruction_pointer += *(int *)vmctx->vm_instruction_pointer;
  
  jump next_handler;
```

### VM EXIT:

Converts registers from VM CONTEXT to actual registers and releases the spinlock.

Therefore, it includes the process of VM CONTEXT -> STACK -> REAL CONTEXT conversion.

```
// Simplified example. Differs from actual implementation.
.themida:14000AEA2  pop r8
.themida:14000AEA4  pop r9
.themida:14000AEA6  pop r10
.themida:14000AEA8  pop r11
.themida:14000AEAA  pop r12
.themida:14000AEAC  pop r13
.themida:14000AEAE  pop r14
.themida:14000AEB0  pop r15
.themida:14000AEB2  pop rdi
.themida:14000AEB3  pop rsi
.themida:14000AEB4  pop rbp
.themida:14000AEB5  pop rbx
.themida:14000AEB6  pop rdx
.themida:14000AEB7  pop rcx
.themida:14000AEB8  pop rax
.themida:14000AEB9  popfq
.themida:14000AEBA  popfq
.themida:14000AEBB  retn    0
```

---

## Handler Operation Principles and Characteristics

1. **Fetching opcode from bytecode**
   - Read 2 bytes using `*(unsigned __int16*)(vm_bytecodePtr + offset)`, then perform XOR/ADD etc. with `vm_handlerKey`.
   - After `& 0xffff` × 8 → Get the "next handler" address from the **handler table**.
2. **VM CONTEXT manipulation**
   - Apply arithmetic/logical operations to `vReg_RAX`, `vReg_RBX`, `vm_flagsA/B`, `field_0[...](stack)`, etc.
   - Instead of EFLAGS, simulate with `vm_flagsA`, or partially obfuscate using pushfq/popfq, __readeflags()/__writeeflags().
3. **Opcodes**
   - Logic like "if (vm_instruction_opcodeN == 0x16) then pop 2 bytes from field_0[...]" is common.
   - Observed upper/lower 4 bits of opcode (`(value & 0xF0)>>4`, `(value & 0xF)`). Concepts like opcodeMain and subOpcode might exist.
4. **Moving to next bytecode**
   - `vm_bytecodePtr += *(int*)(vm_bytecodePtr + someOffset)`
   - Different handlers have different offsets. e.g., +6, +3, +4, etc.

------

## Handler Code Analysis Example

Below is a simplified example of the form of some actual (obfuscated) handlers:

```c
__int64 __fastcall sub_14003411C(VM_CONTEXT *v0) {
  if ((v0->vm_handlerKey & 2) != 0)
    v0->vm_flagsA += 0x7660110;
  // swap(vm_handlerKey, vm_flagsA)
  int tmp = v0->vm_handlerKey;
  v0->vm_handlerKey = v0->vm_flagsA;
  v0->vm_flagsA     = tmp;
  
  // ... Various VM command executions (operand fetch, execution, etc.)
  
  // bytecode fetch
  unsigned int opcode = *(unsigned __int16*)v0->vm_bytecodePtr;
  // next handler = handlerTable[opcode * 8]
  __int64 nextHandler = *( (__int64*)(v0->vm_handlerTable + (opcode & 0xFFFF) * 8) );
  
  // vm_bytecodePtr += *(int*)(v0->vm_bytecodePtr + 3)
  v0->vm_bytecodePtr += *(int*)(v0->vm_bytecodePtr + 3);
  
  // call/jmp nextHandler
  return ((handlerFuncType)nextHandler)(...);
}
```

Thus, a **handler** operates in the order of "(1) Update VM CONTEXT → (2) Extract opcode from bytecode → (3) Calculate next handler address → (4) Move bytecode pointer."

---

## Themida Analyzer Development Ideas

1. Initial Analysis Phase
   - Load the binary and start executing virtualized code at the specified address
   - Set all registers symbolically and emulate instructions using the Triton engine
   - Identify key offsets of vm context (vip/vsp registers, etc.)
   - Symbolize vip/vsp registers to trace subsequent memory accesses
2. Handler Pattern Matching
   - Analyze the AST of values stored in the last store instruction of each handler
   - Match with patterns to understand the operational meaning of the handler
   - Pattern examples:
     - "[vsp] + [vsp]" → ADD
     - "~[vsp] | ~[vsp]" → NAND
     - "[vsp] >> ([vsp] & 0x3f)" → SHR
3. Control Flow Analysis and Transformation
   - Convert identified handlers to basic blocks
   - Slice the RIP register to search for the next basic block address
   - Connect basic blocks to construct a control flow graph
   - Convert all basic blocks to LLVM IR for restoration as executable code
4. Optimization Phase (Optional)
   - Apply LLVM optimization passes
